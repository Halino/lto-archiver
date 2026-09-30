from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from ltobackup.catalog import Catalog
from ltobackup.errors import ValidationError
from ltobackup.scanner import analyze_library
from tests.fixtures import build_frozen_job_fixture


class LinuxScannerTests(unittest.TestCase):
    def _catalog(self, root: Path, source: Path) -> Catalog:
        catalog = Catalog(root / "catalog.db")
        catalog.initialize()
        catalog.add_library("LIB1", "Library 1", str(source))
        return catalog

    def test_scan_excludes_file_and_directory_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            outside = root / "outside"
            source.mkdir()
            outside.mkdir()
            (source / "kept.mxf").write_bytes(b"kept")
            (outside / "outside.mxf").write_bytes(b"outside")
            (source / "file-link.mxf").symlink_to(outside / "outside.mxf")
            (source / "directory-link").symlink_to(outside, target_is_directory=True)
            catalog = self._catalog(root, source)
            try:
                analysis = analyze_library(catalog, "LIB1", 0)
            finally:
                catalog.close()

            self.assertEqual(
                ["kept.mxf"],
                [entry.relative_path for entry in analysis.pending_items],
            )

    def test_scan_rejects_casefold_collision_with_neutral_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "Clip.mxf").write_bytes(b"first")
            (source / "clip.mxf").write_bytes(b"second")
            catalog = self._catalog(root, source)
            try:
                with self.assertRaisesRegex(
                    ValidationError,
                    "Collisione maiuscole/minuscole non portabile",
                ):
                    analyze_library(catalog, "LIB1", 0)
            finally:
                catalog.close()

    def test_changed_ctime_with_same_size_and_mtime_is_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = build_frozen_job_fixture(
                root / "catalog.db", schema_version=41, completed=1, total=4
            )
            source = root / "source-lib1" / "cassette-1" / "file-1.bin"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b"x")
            os.utime(source, ns=(1, 1))
            with Catalog(database) as catalog:
                observed = source.stat().st_ctime_ns
                catalog.connection.execute(
                    "UPDATE file_versions SET source_change_ns=? "
                    "WHERE relative_path='cassette-1/file-1.bin'",
                    (observed - 1,),
                )
                analysis = analyze_library(
                    catalog, "LIB1", 0,
                    source_change_detection_policy="size_mtime_change",
                )
            self.assertEqual(
                ["cassette-1/file-1.bin"],
                [item.relative_path for item in analysis.pending_items],
            )
            self.assertGreater(analysis.pending_items[0].metadata["source_change_ns"], 0)


    def test_matching_ctime_is_archived_without_full_hash(self) -> None:
        from unittest import mock

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = build_frozen_job_fixture(
                root / "catalog.db", schema_version=41, completed=1, total=4
            )
            source = root / "source-lib1" / "cassette-1" / "file-1.bin"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b"x")
            os.utime(source, ns=(1, 1))
            with Catalog(database) as catalog:
                catalog.connection.execute(
                    "UPDATE file_versions SET source_change_ns=? "
                    "WHERE relative_path='cassette-1/file-1.bin'",
                    (source.stat().st_ctime_ns,),
                )
                with mock.patch(
                    "ltobackup.scanner.sha256_file",
                    side_effect=AssertionError("unexpected content hash"),
                ):
                    analysis = analyze_library(
                        catalog, "LIB1", 0,
                        source_change_detection_policy="size_mtime_change",
                    )
            self.assertEqual(1, analysis.archived_files)
            self.assertEqual(0, analysis.legacy_uncovered_files)

    def test_legacy_null_ctime_is_archived_with_partial_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = build_frozen_job_fixture(
                root / "catalog.db", schema_version=41, completed=1, total=4
            )
            source = root / "source-lib1" / "cassette-1" / "file-1.bin"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b"x")
            os.utime(source, ns=(1, 1))
            with Catalog(database) as catalog:
                analysis = analyze_library(
                    catalog, "LIB1", 0,
                    source_change_detection_policy="size_mtime_change",
                )
            self.assertEqual(1, analysis.archived_files)
            self.assertEqual(1, analysis.legacy_uncovered_files)
            self.assertEqual([], list(analysis.pending_items))

    def test_missing_source_ctime_falls_back_without_recopied_terabytes(self) -> None:
        from types import SimpleNamespace
        from unittest import mock

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = build_frozen_job_fixture(
                root / "catalog.db", schema_version=41, completed=1, total=4
            )
            source = root / "source-lib1" / "cassette-1" / "file-1.bin"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b"x")
            os.utime(source, ns=(1, 1))
            original_stat = Path.stat
            actual = source.stat()
            with Catalog(database) as catalog:
                catalog.connection.execute(
                    "UPDATE file_versions SET source_change_ns=? "
                    "WHERE relative_path='cassette-1/file-1.bin'",
                    (actual.st_ctime_ns,),
                )

                def no_source_change(path, *args, **kwargs):
                    result = original_stat(path, *args, **kwargs)
                    if path == source:
                        return SimpleNamespace(
                            st_mode=result.st_mode,
                            st_size=result.st_size,
                            st_mtime_ns=result.st_mtime_ns,
                            st_ctime_ns=0,
                            st_atime_ns=result.st_atime_ns,
                        )
                    return result

                with mock.patch.object(Path, "stat", no_source_change):
                    analysis = analyze_library(
                        catalog, "LIB1", 0,
                        source_change_detection_policy="size_mtime_change",
                    )
            self.assertEqual(1, analysis.archived_files)
            self.assertEqual(1, analysis.legacy_uncovered_files)
            self.assertEqual([], list(analysis.pending_items))
