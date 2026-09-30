"""Cassette-boundary planning must never mutate a written/started cassette."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from ltobackup.catalog import Catalog
from ltobackup.daemon import boundary_replan
from ltobackup.errors import ValidationError
from ltobackup.models import ScanItem


def item(path: str, size: int, *, mtime: int = 1, library: str = "LIB") -> ScanItem:
    return ScanItem(Path("/source") / path, path, size, mtime, library_id=library)


class BoundaryPlannerTests(unittest.TestCase):
    def cassette(self, sequence, label, *, completed=False, attempted=False):
        return boundary_replan.BoundaryCassette(
            sequence=sequence,
            label=label,
            status="completed" if completed else "pending",
            operation="format",
            attempted=attempted,
        )

    def plan(self, items, *, cassettes=None, completed=()):
        return boundary_replan.plan_pending_suffix(
            cassettes=cassettes
            or (
                self.cassette(1, "DONE", completed=True),
                self.cassette(2, "NEXT"),
                self.cassette(3, "SPARE"),
            ),
            scanned_items=tuple(items),
            completed_versions=tuple(completed),
            usable_bytes=10,
            nominal_capacity_bytes=10,
        )

    def test_changed_deleted_and_new_files_replace_only_pending_suffix(self):
        # The old pending manifest is intentionally not an input: a successful
        # fresh scan is the authority for unstarted files, not stale assignments.
        result = self.plan([item("changed", 8, mtime=2), item("new", 3)])
        self.assertEqual(
            [
                (a.sequence, a.label, [i.relative_path for i in a.items])
                for a in result.assignments
            ],
            [(2, "NEXT", ["changed"]), (3, "SPARE", ["new"])],
        )
        self.assertEqual(result.required_additional_labels, 0)

    def test_completed_version_is_not_copied_again_but_changed_version_is(self):
        written = item("written", 4)
        result = self.plan(
            [written, item("updated", 4, mtime=2)],
            completed=[written, item("updated", 4)],
        )
        self.assertEqual(
            [i.relative_path for a in result.assignments for i in a.items], ["updated"]
        )

    def test_surplus_labels_remain_empty_reserves(self):
        result = self.plan([item("one", 3)])
        self.assertEqual([len(a.items) for a in result.assignments], [1, 0])
        self.assertEqual(result.assignments[1].label, "SPARE")

    def test_empty_scan_preserves_labels_without_synthetic_files(self):
        result = self.plan([])
        self.assertEqual([len(a.items) for a in result.assignments], [0, 0])
        self.assertEqual(result.required_additional_labels, 0)

    def test_deficit_is_exact_and_unassigned_files_are_not_dropped(self):
        result = self.plan([item("a", 9), item("b", 9), item("c", 9)])
        self.assertEqual(result.required_additional_labels, 1)
        self.assertEqual(
            [i.relative_path for b in result.unassigned_batches for i in b.items], ["c"]
        )
        self.assertFalse(result.ready)

    def test_layout_is_deterministic_regardless_of_scan_order(self):
        values = [item("b", 6), item("a", 4), item("c", 6)]
        self.assertEqual(self.plan(values), self.plan(list(reversed(values))))

    def test_attempted_cassette_cannot_be_replanned_even_with_zero_bytes(self):
        with self.assertRaisesRegex(ValidationError, "started"):
            self.plan(
                [],
                cassettes=(
                    self.cassette(1, "DONE", completed=True),
                    self.cassette(2, "NEXT", attempted=True),
                ),
            )

    def test_no_boundary_exists_before_first_completed_cassette(self):
        with self.assertRaisesRegex(ValidationError, "completed prefix"):
            self.plan([], cassettes=(self.cassette(1, "NEXT"),))

    def test_completed_cassette_after_pending_is_not_a_safe_suffix(self):
        with self.assertRaises(ValidationError):
            self.plan(
                [],
                cassettes=(
                    self.cassette(1, "DONE", completed=True),
                    self.cassette(2, "NEXT"),
                    self.cassette(3, "LATE", completed=True),
                ),
            )

    def test_duplicate_labels_and_sequences_are_rejected(self):
        for suffix in (
            (self.cassette(2, "NEXT"), self.cassette(3, "next")),
            (self.cassette(2, "NEXT"), self.cassette(2, "SPARE")),
        ):
            with self.subTest(suffix=suffix), self.assertRaises(ValidationError):
                self.plan(
                    [], cassettes=(self.cassette(1, "DONE", completed=True), *suffix)
                )

    def test_duplicate_source_names_fail_instead_of_overwriting_a_version(self):
        with self.assertRaises(ValidationError):
            self.plan([item("a", 1), item("A", 2)])

    def test_distinct_libraries_may_have_the_same_relative_path(self):
        result = self.plan([item("a", 1, library="ONE"), item("a", 1, library="TWO")])
        self.assertEqual(sum(len(a.items) for a in result.assignments), 2)

    def test_ltfs_metadata_overhead_is_included_in_real_media_estimate(self):
        mib = 1024**2
        # One 1 MiB file consumes 2 MiB plus a 4 MiB library block. Two
        # files consume 8 MiB, so a 7 MiB budget needs two cassettes.
        result = boundary_replan.plan_pending_suffix(
            cassettes=(
                self.cassette(1, "DONE", completed=True),
                self.cassette(2, "NEXT"),
                self.cassette(3, "SPARE"),
            ),
            scanned_items=(item("a", mib), item("b", mib)),
            completed_versions=(),
            usable_bytes=7 * mib,
            nominal_capacity_bytes=1_500_000_000_000,
        )
        self.assertEqual([len(a.items) for a in result.assignments], [1, 1])


class BoundaryScanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.catalog = Catalog(self.root / "catalog.db")
        self.catalog.initialize()
        self.catalog.add_library("LIB", "Library", str(self.source))
        self.addCleanup(self.catalog.close)

    def verify(self, library):
        root = Path(library["source_root"])
        stat = root.stat()
        return str(root), f"{stat.st_dev}:{stat.st_ino}"

    def scan(self, verify=None):
        return boundary_replan.scan_boundary_sources(
            self.catalog,
            ("LIB",),
            verify_library=verify or self.verify,
            minimum_age_seconds=0,
        )

    def test_rescan_observes_added_changed_removed_files_without_catalog_writes(self):
        (self.source / "old").write_bytes(b"old")
        (self.source / "changed").write_bytes(b"a")
        first = self.scan()
        self.assertEqual([i.relative_path for i in first], ["changed", "old"])
        (self.source / "old").unlink()
        (self.source / "changed").write_bytes(b"updated")
        (self.source / "new").write_bytes(b"new")
        before = self.catalog.connection.total_changes
        second = self.scan()
        self.assertEqual(
            [(i.relative_path, i.size, i.library_id) for i in second],
            [("changed", 7, "LIB"), ("new", 3, "LIB")],
        )
        self.assertEqual(self.catalog.connection.total_changes, before)

    def test_missing_root_is_a_failure_not_a_successful_empty_scan(self):
        self.source.rmdir()
        with self.assertRaises((OSError, ValidationError)):
            self.scan()

    def test_share_disappearing_after_walk_rejects_entire_scan(self):
        (self.source / "file").write_bytes(b"payload")
        calls = 0

        def disappears(library):
            nonlocal calls
            calls += 1
            if calls == 2:
                shutil.rmtree(self.source)
            return self.verify(library)

        with self.assertRaises((OSError, ValidationError)):
            self.scan(disappears)

    def test_changed_identity_after_walk_rejects_entire_scan(self):
        (self.source / "file").write_bytes(b"payload")
        calls = 0

        def changes(library):
            nonlocal calls
            calls += 1
            root, identity = self.verify(library)
            return root, identity if calls == 1 else "different-export"

        with self.assertRaises(ValidationError):
            self.scan(changes)

    def test_no_symlink_source_can_redirect_boundary_scan(self):
        self.source.rmdir()
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "secret").write_bytes(b"secret")
        self.source.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValidationError):
            self.scan()

    def test_scan_rechecks_earlier_library_after_later_library(self):
        other = self.root / "other"
        other.mkdir()
        self.catalog.add_library("OTHER", "Other", str(other))
        seen_other = False

        def changes(library):
            nonlocal seen_other
            root, identity = self.verify(library)
            if library["id"] == "OTHER":
                seen_other = True
            if library["id"] == "LIB" and seen_other:
                identity = "replacement"
            return root, identity

        with self.assertRaises(ValidationError):
            boundary_replan.scan_boundary_sources(
                self.catalog,
                ("LIB", "OTHER"),
                verify_library=changes,
                minimum_age_seconds=0,
            )

    def test_missing_file_after_walk_invalidates_candidate(self):
        path = self.source / "file"
        path.write_bytes(b"payload")
        calls = 0

        def disappears(library):
            nonlocal calls
            calls += 1
            if calls == 2:
                path.unlink()
            return self.verify(library)

        with self.assertRaises((OSError, ValidationError)):
            self.scan(disappears)

    def test_same_metadata_content_change_survives_full_hash_scan(self):
        path = self.source / "file"
        path.write_bytes(b"old")
        original = path.stat()
        self.catalog.register_tape("TAPE", "TAPE", "Tape", "LTFS", "/tape")
        self.catalog.create_block("BLOCK", "LIB", "TAPE", "blocks/BLOCK", 1, 3)
        self.catalog.record_file_version(
            "LIB",
            "BLOCK",
            "TAPE",
            "file",
            "blocks/BLOCK/files/file",
            3,
            original.st_mtime_ns,
            hashlib.sha256(b"old").hexdigest(),
        )
        self.catalog.complete_block("BLOCK")
        self.assertEqual(self.scan(), ())
        path.write_bytes(b"new")
        os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
        result = boundary_replan.scan_boundary_sources(
            self.catalog,
            ("LIB",),
            verify_library=self.verify,
            minimum_age_seconds=0,
            verify_unchanged_content=True,
        )
        self.assertEqual([i.relative_path for i in result], ["file"])


if __name__ == "__main__":
    unittest.main()
