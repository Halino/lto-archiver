from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ltobackup.catalog import Catalog
from ltobackup.daemon import native_frozen
from ltobackup.errors import CatalogError
from ltobackup.managed_sources import ManagedSourceAdmissionError


class SourceInspectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.files = [self.source / "first.bin", self.source / "next.bin"]
        for path in self.files:
            path.write_bytes(b"payload")
        self.catalog = Catalog(self.root / "catalog.db")
        self.addCleanup(self.catalog.close)
        self.catalog.initialize()
        self.catalog.add_library("LIB", "Library", str(self.source))
        self.catalog.create_automatic_job(
            "JOB", "LIB", "TAPE0", "AUTO",
            [("ONE", "ONE", 1, 7), ("TWO", "TWO", 1, 7)],
            force_format=True,
        )
        for sequence, path in enumerate(self.files, 1):
            self.catalog.replace_automatic_cassette_manifest(
                "JOB", sequence, [("LIB", path.name, 7, path.stat().st_mtime_ns)]
            )
        self.before = self.catalog.connection.iterdump()
        self.before = "\n".join(self.before)

    def inspect(self, verifier=None):
        inspect = getattr(native_frozen, "inspect_cassette_sources", None)
        self.assertTrue(callable(inspect), "cassette boundary source inspection is missing")
        return inspect(
            self.catalog, "JOB", 2,
            verify_library=verifier or (lambda row: (str(self.source), "identity")),
        )

    def test_only_next_assignment_is_checked_and_catalog_is_unchanged(self):
        self.files[0].unlink()
        (self.source / "new.bin").write_bytes(b"new version for a later extension")
        result = self.inspect()
        self.assertEqual("ready", result["state"])
        self.assertEqual(1, result["checked_files"])
        self.assertEqual([], result["issues"])
        self.assertEqual(self.before, "\n".join(self.catalog.connection.iterdump()))

    def test_missing_file_is_reported_without_skipping_or_replanning(self):
        self.files[1].unlink()
        result = self.inspect()
        self.assertEqual("blocked", result["state"])
        self.assertEqual(1, result["missing_files"])
        self.assertEqual([{"library_id": "LIB", "relative_path": "next.bin",
                           "code": "source_missing"}], result["issues"])
        self.assertEqual(self.before, "\n".join(self.catalog.connection.iterdump()))

    def test_changed_file_is_reported(self):
        self.files[1].write_bytes(b"changed payload")
        result = self.inspect()
        self.assertEqual("blocked", result["state"])
        self.assertEqual(1, result["changed_files"])
        self.assertEqual("source_changed", result["issues"][0]["code"])

    def test_unavailable_share_is_not_reported_as_deleted_files(self):
        self.files[1].unlink()

        def unavailable(_row):
            raise OSError("share unavailable with private diagnostic")

        result = self.inspect(unavailable)
        self.assertEqual("source_unavailable", result["state"])
        self.assertEqual(0, result["missing_files"])
        self.assertEqual(1, result["unavailable_libraries"])
        self.assertNotIn("private diagnostic", json.dumps(result))

    def test_share_loss_during_check_discards_missing_classification(self):
        self.files[1].unlink()
        calls = 0

        def unstable(_row):
            nonlocal calls
            calls += 1
            if calls > 1:
                raise OSError("share lost")
            return str(self.source), "identity"

        result = self.inspect(unstable)
        self.assertEqual("source_unavailable", result["state"])
        self.assertEqual(0, result["missing_files"])

    def test_replaced_library_identity_is_unavailable_not_missing(self):
        calls = 0

        def changed_identity(_row):
            nonlocal calls
            calls += 1
            return str(self.source), str(calls)

        result = self.inspect(changed_identity)
        self.assertEqual("source_unavailable", result["state"])
        self.assertEqual(0, result["changed_files"])

    def test_symlinked_file_is_not_followed(self):
        self.files[1].unlink()
        self.files[1].symlink_to(self.root / "outside")
        result = self.inspect()
        self.assertEqual("source_changed", result["issues"][0]["code"])

    def test_permission_failure_is_not_a_missing_file(self):
        original = Path.lstat

        def denied(path):
            if path == self.files[1]:
                raise PermissionError("denied")
            return original(path)

        with patch.object(Path, "lstat", denied):
            result = self.inspect()
        self.assertEqual("source_unavailable", result["state"])
        self.assertEqual(0, result["missing_files"])

    def test_real_managed_share_rejection_is_reported_without_exception_details(self):
        def unavailable(_row):
            raise ManagedSourceAdmissionError()

        result = self.inspect(unavailable)
        self.assertEqual("source_unavailable", result["state"])
        self.assertNotIn("private mount detail", json.dumps(result))

    def test_directory_replaced_by_file_is_a_changed_source(self):
        with self.catalog.transaction() as db:
            db.execute("UPDATE automatic_cassette_items SET relative_path='folder/next.bin' "
                       "WHERE job_id='JOB' AND sequence=2")
        (self.source / "folder").write_bytes(b"not a directory")
        result = self.inspect()
        self.assertEqual("blocked", result["state"])
        self.assertEqual(1, result["changed_files"])
        self.assertEqual(0, result["unavailable_libraries"])

    def test_issue_examples_are_bounded_but_counts_are_exact(self):
        self.catalog.add_library("MANYLIB", "Many files", str(self.source))
        self.catalog.create_automatic_job(
            "MANY", "MANYLIB", "TAPE0", "AUTO", [("THREE", "THREE", 105, 105)],
            force_format=True,
        )
        self.catalog.replace_automatic_cassette_manifest(
            "MANY", 1, [("MANYLIB", f"missing-{index}.bin", 1, 0) for index in range(105)]
        )
        result = native_frozen.inspect_cassette_sources(
            self.catalog, "MANY", 1,
            verify_library=lambda _row: (str(self.source), "identity"),
        )
        self.assertEqual(105, result["missing_files"])
        self.assertEqual(100, len(result["issues"]))

    def test_invalid_manifest_path_is_not_a_share_outage(self):
        with self.catalog.transaction() as db:
            db.execute("UPDATE automatic_cassette_items SET relative_path='../outside' "
                       "WHERE job_id='JOB' AND sequence=2")
        with self.assertRaises(CatalogError):
            self.inspect()
