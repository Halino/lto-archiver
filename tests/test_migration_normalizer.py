from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import sqlite3
import stat
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from ltobackup.migration.archive import read_bundle
from ltobackup.migration.models import MigrationRejected
from ltobackup.migration.normalizer import (
    MAX_CAPTURE_MEMBER_BYTES,
    SEALED_CAPTURE_SHA256,
    normalize_capture,
)
from tests.fixtures import build_frozen_job_fixture

_CAPTURE_NAMES = (
    "SHA256SUMS-post-close",
    "capture-summary-post-close.json",
    "catalog-closed-consistent.db",
    "catalog-closed-source.db",
    "catalog-export.json",
    "config.json",
    "lto-backup.log",
    "ltfs-mount.log",
)
_HASHED_CAPTURE_NAMES = _CAPTURE_NAMES[2:]
_CANONICAL_NAMES = (
    "SHA256SUMS",
    "acceptance.json",
    "catalog.db",
    "provenance.json",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _checksum_manifest(members: dict[str, bytes]) -> bytes:
    return "".join(
        f"{_sha256(members[name])}  {name}\n" for name in _HASHED_CAPTURE_NAMES
    ).encode("ascii")


def _regular_entry(name: str, payload: bytes) -> tuple[tarfile.TarInfo, bytes]:
    entry = tarfile.TarInfo(name)
    entry.size = len(payload)
    entry.mode = 0o640
    entry.mtime = 0
    return entry, payload


def _write_tar(path: Path, entries: list[tuple[tarfile.TarInfo, bytes]]) -> Path:
    with tarfile.open(path, mode="w:gz", format=tarfile.GNU_FORMAT) as archive:
        for entry, payload in entries:
            archive.addfile(entry, io.BytesIO(payload) if entry.isfile() else None)
    return path


def _tar_bytes(entries: list[tuple[tarfile.TarInfo, bytes]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for entry, payload in entries:
            archive.addfile(entry, io.BytesIO(payload) if entry.isfile() else None)
    return output.getvalue()


class MigrationNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.capture = self.root / "capture.tar.gz"
        self.members = self._valid_members()
        self._write_members(self.capture, self.members)
        self.capture_sha256 = _sha256(self.capture.read_bytes())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _valid_members(self) -> dict[str, bytes]:
        database = self.root / "catalog.db"
        build_frozen_job_fixture(
            database,
            completed=3,
            total=20,
            schema_version=13,
            fourth_status="waiting_media",
        )
        catalog = database.read_bytes()
        payloads = {
            "catalog-closed-consistent.db": catalog,
            "catalog-closed-source.db": catalog,
            "catalog-export.json": b"{}\n",
            "config.json": b"{}\n",
            "lto-backup.log": b"",
            "ltfs-mount.log": b"sanitized mount evidence\n",
        }
        source_hash = _sha256(payloads["catalog-closed-source.db"])
        summary = {
            "captured_at_utc": "2026-08-21T13:17:06Z",
            "source_host": "sanitized-windows-host",
            "application_version": "0.11.26",
            "schema_version": 13,
            "job": {
                "status": "waiting_media",
                "current_sequence": 4,
                "total_cassettes": 20,
                "completed_sequences": [1, 2, 3],
                "next_cassette_status": "waiting_media",
                "last_error": None,
            },
            "quiescence": {
                "automatic_job_lock_held": False,
                "gui_process_count": 0,
                "ltfs_process_count": 0,
                "ltfs_volume_count": 0,
                "source_catalog_sha256": source_hash,
                "source_catalog_modified_utc": "2026-08-21T13:16:24Z",
            },
            "validation": {
                "sqlite_integrity_check": "ok",
                "foreign_key_violations": 0,
                "uncommitted_blocks": 0,
                "assignment_gaps": 0,
                "duplicate_assignments": 0,
                "completed_cassettes_match_planned_files_and_bytes": True,
                "next_cassette_has_no_committed_or_provisional_write": True,
                "assignment_rows": 17,
                "completed_file_versions": 3,
            },
            "catalog_files": {
                "catalog-closed-consistent.db": "authoritative backup",
                "catalog-closed-source.db": "forensic source",
                "catalog-export.json": "corroborating export",
            },
            "cutover_note": "No media was accessed while sealing this capture.",
        }
        return {
            "SHA256SUMS-post-close": _checksum_manifest(payloads),
            "capture-summary-post-close.json": _canonical_json(summary),
            **payloads,
        }

    def _write_members(self, path: Path, members: dict[str, bytes]) -> Path:
        return _write_tar(
            path,
            [
                _regular_entry(name, members[name])
                for name in _CAPTURE_NAMES
                if name in members
            ],
        )

    def _normalize(self, capture: Path | None = None, name: str = "bundle.zip"):
        capture = capture or self.capture
        return normalize_capture(
            capture,
            self.root / name,
            expected_archive_sha256=_sha256(capture.read_bytes()),
        )

    def _assert_rejected_immutably(
        self, capture: Path, pattern: str, *, name: str = "rejected.zip"
    ) -> None:
        before = capture.read_bytes()
        with self.assertRaisesRegex(MigrationRejected, pattern):
            self._normalize(capture, name)
        self.assertEqual(before, capture.read_bytes())
        self.assertFalse((self.root / name).exists())

    def test_normalizes_without_mutating_source_and_excludes_raw_evidence(self) -> None:
        before = self.capture.read_bytes()
        before_mtime = self.capture.stat().st_mtime_ns

        bundle = self._normalize()

        self.assertEqual(before, self.capture.read_bytes())
        self.assertEqual(before_mtime, self.capture.stat().st_mtime_ns)
        self.assertEqual(_CANONICAL_NAMES, bundle.member_names)
        self.assertTrue(bundle.acceptance.accepted)
        self.assertEqual("JOB-MIGRATION", bundle.acceptance.job_id)
        self.assertEqual(4, bundle.acceptance.next_sequence)
        self.assertEqual((1, 2, 3), bundle.acceptance.completed_sequences)
        self.assertEqual((), bundle.acceptance.media_accesses)
        self.assertEqual(
            self.capture_sha256, bundle.provenance["source_archive_sha256"]
        )
        self.assertEqual(
            _sha256(self.members["catalog-closed-consistent.db"]),
            bundle.provenance["authoritative_catalog_sha256"],
        )
        self.assertEqual(
            set(_HASHED_CAPTURE_NAMES),
            set(bundle.provenance["source_member_sha256"]),
        )
        with zipfile.ZipFile(bundle.path) as archive:
            self.assertEqual(list(_CANONICAL_NAMES), archive.namelist())
            for forbidden in (
                "catalog-closed-source.db",
                "catalog-export.json",
                "config.json",
                "lto-backup.log",
                "ltfs-mount.log",
            ):
                self.assertNotIn(forbidden, archive.namelist())
        self.assertEqual(0o600, stat.S_IMODE(bundle.path.stat().st_mode))

        extracted = self.root / "extracted-catalog.db"
        bundle.extract_catalog(extracted)
        self.assertEqual(0o600, stat.S_IMODE(extracted.stat().st_mode))
        self.assertEqual(bundle.catalog_sha256, _sha256(extracted.read_bytes()))
        before_extracted = extracted.read_bytes()
        with self.assertRaisesRegex(MigrationRejected, "destination-exists"):
            bundle.extract_catalog(extracted)
        self.assertEqual(before_extracted, extracted.read_bytes())

    def test_normalization_is_byte_deterministic_and_destination_is_exclusive(
        self,
    ) -> None:
        first = self._normalize(name="first.zip")
        second = self._normalize(name="second.zip")
        self.assertEqual(first.path.read_bytes(), second.path.read_bytes())
        self.assertEqual(first.bundle_sha256, second.bundle_sha256)

        original = first.path.read_bytes()
        with self.assertRaisesRegex(MigrationRejected, "destination-exists"):
            normalize_capture(
                self.capture,
                first.path,
                expected_archive_sha256=self.capture_sha256,
            )
        self.assertEqual(original, first.path.read_bytes())

    def test_default_sealed_capture_hash_is_pinned(self) -> None:
        self.assertEqual(
            "664c0a3a320bf789204895a552f28fcf60937dca93622cacd5a7407308b5b440",
            SEALED_CAPTURE_SHA256,
        )
        before = self.capture.read_bytes()
        with self.assertRaisesRegex(MigrationRejected, "capture-sha256-mismatch"):
            normalize_capture(self.capture, self.root / "default.zip")
        self.assertEqual(before, self.capture.read_bytes())
        self.assertFalse((self.root / "default.zip").exists())

    def test_rejects_missing_and_extra_members(self) -> None:
        missing = dict(self.members)
        missing.pop("config.json")
        missing_capture = self._write_members(self.root / "missing.tar.gz", missing)
        self._assert_rejected_immutably(missing_capture, "capture-members-invalid")

        extra_entries = [
            _regular_entry(name, self.members[name]) for name in _CAPTURE_NAMES
        ]
        extra_entries.append(_regular_entry("unexpected.txt", b"unexpected"))
        extra_capture = _write_tar(self.root / "extra.tar.gz", extra_entries)
        self._assert_rejected_immutably(
            extra_capture, "capture-member-name-invalid", name="extra.zip"
        )

    def test_rejects_duplicate_absolute_and_traversal_members(self) -> None:
        duplicate_entries = [
            _regular_entry(name, self.members[name]) for name in _CAPTURE_NAMES
        ]
        duplicate_entries.append(_regular_entry("config.json", b"duplicate"))
        duplicate = _write_tar(self.root / "duplicate.tar.gz", duplicate_entries)
        self._assert_rejected_immutably(
            duplicate, "capture-member-duplicate", name="duplicate.zip"
        )

        for index, unsafe_name in enumerate(("/config.json", "../config.json")):
            with self.subTest(name=unsafe_name):
                entries = [
                    _regular_entry(name, self.members[name])
                    for name in _CAPTURE_NAMES
                    if name != "config.json"
                ]
                entries.append(_regular_entry(unsafe_name, self.members["config.json"]))
                capture = _write_tar(self.root / f"unsafe-{index}.tar.gz", entries)
                self._assert_rejected_immutably(
                    capture, "capture-member-name-invalid", name=f"unsafe-{index}.zip"
                )

    def test_rejects_member_hidden_after_tar_end_markers(self) -> None:
        visible = _tar_bytes(
            [_regular_entry(name, self.members[name]) for name in _CAPTURE_NAMES]
        )
        hidden = _tar_bytes([_regular_entry("unexpected.txt", b"hidden")])
        capture = self.root / "hidden-after-eof.tar.gz"
        capture.write_bytes(gzip.compress(visible + hidden))

        self._assert_rejected_immutably(
            capture, "capture-member-name-invalid", name="hidden-after-eof.zip"
        )

    def test_rejects_allowed_member_hidden_after_tar_end_markers(self) -> None:
        visible = _tar_bytes(
            [
                _regular_entry(name, self.members[name])
                for name in _CAPTURE_NAMES
                if name != "config.json"
            ]
        )
        hidden = _tar_bytes(
            [_regular_entry("config.json", self.members["config.json"])]
        )
        capture = self.root / "allowed-hidden-after-eof.tar.gz"
        capture.write_bytes(gzip.compress(visible + hidden))

        self._assert_rejected_immutably(
            capture, "capture-malformed", name="allowed-hidden-after-eof.zip"
        )

    def test_rejects_links_and_special_members(self) -> None:
        for index, member_type in enumerate(
            (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE)
        ):
            with self.subTest(member_type=member_type):
                entries = [
                    _regular_entry(name, self.members[name])
                    for name in _CAPTURE_NAMES
                    if name != "config.json"
                ]
                unsafe = tarfile.TarInfo("config.json")
                unsafe.type = member_type
                unsafe.linkname = "catalog-closed-consistent.db"
                entries.append((unsafe, b""))
                capture = _write_tar(self.root / f"special-{index}.tar.gz", entries)
                self._assert_rejected_immutably(
                    capture,
                    "capture-member-type-invalid",
                    name=f"special-{index}.zip",
                )

    def test_rejects_pax_and_gnu_extension_headers(self) -> None:
        pax_entries = [
            _regular_entry(name, self.members[name]) for name in _CAPTURE_NAMES
        ]
        pax_entries[5][0].pax_headers = {"comment": "forbidden-extension"}
        pax = self.root / "pax-extension.tar.gz"
        with tarfile.open(pax, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
            for entry, payload in pax_entries:
                archive.addfile(entry, io.BytesIO(payload))
        self._assert_rejected_immutably(
            pax, "capture-member-type-invalid", name="pax-extension.zip"
        )

        gnu_entries = [
            _regular_entry(name, self.members[name])
            for name in _CAPTURE_NAMES
            if name != "config.json"
        ]
        longname = tarfile.TarInfo("././@LongLink")
        longname.type = tarfile.GNUTYPE_LONGNAME
        longname_payload = b"config.json\0"
        longname.size = len(longname_payload)
        actual = tarfile.TarInfo("ignored")
        actual.size = len(self.members["config.json"])
        gnu_entries.extend(
            [(longname, longname_payload), (actual, self.members["config.json"])]
        )
        gnu = _write_tar(self.root / "gnu-extension.tar.gz", gnu_entries)
        self._assert_rejected_immutably(
            gnu, "capture-malformed", name="gnu-extension.zip"
        )

    def test_rejects_corrupt_truncated_and_encrypted_or_malformed_input(self) -> None:
        truncated = self.root / "truncated.tar.gz"
        truncated.write_bytes(self.capture.read_bytes()[:-12])
        self._assert_rejected_immutably(
            truncated, "capture-malformed", name="truncated.zip"
        )

        encrypted = self.root / "encrypted.tar.gz"
        encrypted.write_bytes(b"-----BEGIN PGP MESSAGE-----\nnot-a-tar\n")
        self._assert_rejected_immutably(
            encrypted, "capture-encrypted-or-malformed", name="encrypted.zip"
        )

        concatenated = self.root / "concatenated.tar.gz"
        concatenated.write_bytes(self.capture.read_bytes() + gzip.compress(b"hidden"))
        self._assert_rejected_immutably(
            concatenated, "capture-malformed", name="concatenated.zip"
        )

    def test_rejects_declared_and_aggregate_size_bombs(self) -> None:
        oversized = tarfile.TarInfo("catalog-closed-consistent.db")
        oversized.size = MAX_CAPTURE_MEMBER_BYTES["catalog-closed-consistent.db"] + 1
        declared = self.root / "declared-size.tar.gz"
        declared.write_bytes(gzip.compress(oversized.tobuf(format=tarfile.GNU_FORMAT)))
        self._assert_rejected_immutably(
            declared, "capture-member-too-large", name="declared-size.zip"
        )

        large_members = dict(self.members)
        large_members["catalog-closed-consistent.db"] = b"0" * (21 * 1024 * 1024)
        large_members["catalog-closed-source.db"] = b"1" * (21 * 1024 * 1024)
        large_members["SHA256SUMS-post-close"] = _checksum_manifest(large_members)
        aggregate = self._write_members(
            self.root / "aggregate-size.tar.gz", large_members
        )
        self._assert_rejected_immutably(
            aggregate, "capture-size-limit", name="aggregate-size.zip"
        )

    def test_rejects_checksum_coverage_and_syntax_errors(self) -> None:
        valid_lines = self.members["SHA256SUMS-post-close"].decode("ascii").splitlines()
        variants = {
            "missing": "\n".join(valid_lines[:-1]) + "\n",
            "extra": "\n".join(valid_lines) + f"\n{'0' * 64}  unexpected.txt\n",
            "duplicate": "\n".join(valid_lines + [valid_lines[0]]) + "\n",
            "malformed": valid_lines[0].upper()
            + "\n"
            + "\n".join(valid_lines[1:])
            + "\n",
        }
        for index, (case, manifest) in enumerate(variants.items()):
            with self.subTest(case=case):
                members = dict(self.members)
                members["SHA256SUMS-post-close"] = manifest.encode("ascii")
                capture = self._write_members(
                    self.root / f"manifest-{index}.tar.gz", members
                )
                self._assert_rejected_immutably(
                    capture,
                    "capture-checksums-invalid",
                    name=f"manifest-{index}.zip",
                )

    def test_rejects_payload_hash_mismatch(self) -> None:
        members = dict(self.members)
        members["config.json"] = b'{"tampered":true}\n'
        capture = self._write_members(self.root / "hash-mismatch.tar.gz", members)
        self._assert_rejected_immutably(
            capture, "capture-member-sha256-mismatch", name="hash-mismatch.zip"
        )

    def test_rejects_summary_disagreement_and_validator_failure(self) -> None:
        summary_members = dict(self.members)
        summary = json.loads(summary_members["capture-summary-post-close.json"])
        summary["validation"]["assignment_rows"] += 1
        summary_members["capture-summary-post-close.json"] = _canonical_json(summary)
        capture = self._write_members(
            self.root / "summary-mismatch.tar.gz", summary_members
        )
        self._assert_rejected_immutably(
            capture, "capture-summary-mismatch", name="summary-mismatch.zip"
        )

        invalid_database = self.root / "invalid.db"
        invalid_database.write_bytes(self.members["catalog-closed-consistent.db"])
        with sqlite3.connect(invalid_database) as connection:
            connection.execute(
                "UPDATE automatic_jobs SET status='writing' WHERE id='JOB-MIGRATION'"
            )
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        validator_members = dict(self.members)
        validator_members["catalog-closed-consistent.db"] = (
            invalid_database.read_bytes()
        )
        validator_members["SHA256SUMS-post-close"] = _checksum_manifest(
            validator_members
        )
        validator_capture = self._write_members(
            self.root / "validator-rejected.tar.gz", validator_members
        )
        self._assert_rejected_immutably(
            validator_capture, "job-not-waiting", name="validator-rejected.zip"
        )

    def test_rejects_boolean_summary_value_where_integer_is_required(self) -> None:
        members = dict(self.members)
        summary = json.loads(members["capture-summary-post-close.json"])
        summary["quiescence"]["gui_process_count"] = False
        members["capture-summary-post-close.json"] = _canonical_json(summary)
        capture = self._write_members(self.root / "summary-bool.tar.gz", members)

        self._assert_rejected_immutably(
            capture, "capture-summary-invalid", name="summary-bool.zip"
        )

    def test_rejects_schema_other_than_exact_sealed_schema_thirteen(self) -> None:
        database = self.root / "schema-fourteen.db"
        build_frozen_job_fixture(
            database,
            completed=3,
            total=20,
            schema_version=14,
            fourth_status="waiting_media",
        )
        catalog = database.read_bytes()
        members = dict(self.members)
        members["catalog-closed-consistent.db"] = catalog
        members["catalog-closed-source.db"] = catalog
        summary = json.loads(members["capture-summary-post-close.json"])
        summary["schema_version"] = 14
        summary["quiescence"]["source_catalog_sha256"] = _sha256(catalog)
        members["capture-summary-post-close.json"] = _canonical_json(summary)
        members["SHA256SUMS-post-close"] = _checksum_manifest(members)
        capture = self._write_members(self.root / "schema-fourteen.tar.gz", members)

        self._assert_rejected_immutably(
            capture, "capture-schema-invalid", name="schema-fourteen.zip"
        )

    def test_malformed_catalog_schema_is_a_migration_rejection(self) -> None:
        database = self.root / "malformed-schema.db"
        database.write_bytes(self.members["catalog-closed-consistent.db"])
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE metadata SET value='not-an-integer' WHERE key='schema_version'"
            )
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        members = dict(self.members)
        members["catalog-closed-consistent.db"] = database.read_bytes()
        members["SHA256SUMS-post-close"] = _checksum_manifest(members)
        capture = self._write_members(self.root / "malformed-schema.tar.gz", members)

        self._assert_rejected_immutably(
            capture, "capture-catalog-invalid", name="malformed-schema.zip"
        )

    def test_canonical_reader_rejects_tampering(self) -> None:
        bundle = self._normalize()
        with zipfile.ZipFile(bundle.path) as source:
            members = {name: source.read(name) for name in source.namelist()}
        members["catalog.db"] += b"tampered"
        tampered = self.root / "tampered.zip"
        with zipfile.ZipFile(
            tampered, mode="x", compression=zipfile.ZIP_STORED
        ) as archive:
            for name in _CANONICAL_NAMES:
                archive.writestr(name, members[name])
        before = tampered.read_bytes()
        with self.assertRaisesRegex(MigrationRejected, "bundle-member-sha256-mismatch"):
            read_bundle(tampered)
        self.assertEqual(before, tampered.read_bytes())

    def test_canonical_reader_rejects_carrier_bytes_and_metadata_variants(self) -> None:
        bundle = self._normalize()
        original = bundle.path.read_bytes()
        prefixed = self.root / "prefixed.zip"
        prefixed.write_bytes(b"RAW-WINDOWS-CONFIG-SECRET\n" + original)
        suffixed = self.root / "suffixed.zip"
        suffixed.write_bytes(original + b"RAW-TRAILING-SECRET")

        with zipfile.ZipFile(bundle.path) as source:
            members = {name: source.read(name) for name in source.namelist()}
        metadata_variant = self.root / "metadata-variant.zip"
        with zipfile.ZipFile(
            metadata_variant, mode="x", compression=zipfile.ZIP_STORED
        ) as archive:
            for name in reversed(_CANONICAL_NAMES):
                info = zipfile.ZipInfo(name, date_time=(2026, 8, 21, 20, 0, 0))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.extra = b"\xfe\xca\x06\x00SECRET"
                info.comment = b"raw-config-secret"
                archive.writestr(info, members[name])

        for candidate in (prefixed, suffixed, metadata_variant):
            with self.subTest(candidate=candidate.name):
                before = candidate.read_bytes()
                with self.assertRaisesRegex(MigrationRejected, "bundle-noncanonical"):
                    read_bundle(candidate)
                self.assertEqual(before, candidate.read_bytes())

    def test_canonical_reader_rejects_symlink_and_oversized_outer_file(self) -> None:
        bundle = self._normalize()
        symlink = self.root / "bundle-link.zip"
        symlink.symlink_to(bundle.path)
        with self.assertRaisesRegex(MigrationRejected, "bundle-not-regular"):
            read_bundle(symlink)

        oversized = self.root / "oversized.zip"
        with oversized.open("wb") as handle:
            handle.seek(36 * 1024 * 1024)
            handle.write(b"x")
        with self.assertRaisesRegex(MigrationRejected, "bundle-size-limit"):
            read_bundle(oversized)

    def test_canonical_reader_rejects_fifo_directory_and_read_race(self) -> None:
        bundle = self._normalize()

        fifo = self.root / "bundle.fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(MigrationRejected, "bundle-not-regular"):
            read_bundle(fifo)

        directory = self.root / "bundle-directory"
        directory.mkdir()
        with self.assertRaisesRegex(MigrationRejected, "bundle-not-regular"):
            read_bundle(directory)

        before = bundle.path.stat()
        after = mock.Mock(wraps=before)
        after.st_ctime_ns = before.st_ctime_ns + 1
        observations = iter((before, after))
        real_fstat = os.fstat

        def observed_fstat(descriptor: int):
            try:
                return next(observations)
            except StopIteration:
                return real_fstat(descriptor)

        with (
            mock.patch(
                "ltobackup.migration.archive.os.fstat",
                side_effect=observed_fstat,
            ),
            self.assertRaisesRegex(MigrationRejected, "bundle-changed-during-read"),
        ):
            read_bundle(bundle.path)


if __name__ == "__main__":
    unittest.main()
