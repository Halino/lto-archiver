from __future__ import annotations

import errno
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from ltobackup.catalog import SCHEMA_VERSION, Catalog
from ltobackup.errors import ValidationError
from ltobackup.tape.manifests import BlockManifest, FileManifestRecord, ManifestWriter


class LinuxManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tape_root = self.root / "ltfs"
        self.tape_root.mkdir()
        self.host_state = self.root / "host-state"
        self.host_state.mkdir()
        self.database = self.root / "catalog.sqlite3"
        self.catalog = Catalog(self.database)
        self.catalog.initialize()
        self.addCleanup(self.catalog.close)
        source = self.root / "source"
        source.mkdir()
        self.catalog.add_library("LIB1", "Library 1", str(source))
        self.catalog.register_tape(
            "TAPE04",
            "SERIAL04",
            "TAPE04",
            "LTFS",
            str(self.tape_root),
            cassette_number="CASSETTE-4",
        )
        self.catalog.create_block(
            "BLOCK4",
            "LIB1",
            "TAPE04",
            "libraries/LIB1/blocks/BLOCK4",
            1,
            4,
        )
        self.staging_path = self.host_state / "BLOCK4.manifest.jsonl"
        self.manifest_path = (
            self.tape_root
            / "libraries"
            / "LIB1"
            / "blocks"
            / "BLOCK4"
            / "manifest.jsonl"
        )
        self.block_path = self.manifest_path.with_name("block.json")
        self.snapshot_path = (
            self.tape_root / ".lto-backup" / "catalog-snapshots" / "BLOCK4.sqlite3"
        )
        self.writer = ManifestWriter(
            self.catalog,
            self.staging_path,
            self.manifest_path,
            self.block_path,
            self.snapshot_path,
            buffer_bytes=8,
            tape_root=self.tape_root,
        )
        self.addCleanup(self.writer.close)
        self.record = FileManifestRecord(
            library_id="LIB1",
            relative_path="clip.mxf",
            tape_relative_path="libraries/LIB1/blocks/BLOCK4/files/clip.mxf",
            size=4,
            mtime_ns=123,
            sha256="a" * 64,
        )
        self.block = BlockManifest(
            block_id="BLOCK4",
            library_id="LIB1",
            tape_id="TAPE04",
            completed_at="2026-08-21T12:00:00+00:00",
            file_count=1,
            total_bytes=4,
        )

    def test_linux_manifest_matches_portable_windows_fields_and_encoding(self) -> None:
        """A missing portable field or nondeterministic JSON breaks recovery."""
        self.writer.append(self.record)

        payload = self.staging_path.read_bytes()
        parsed = json.loads(payload.decode("utf-8").splitlines()[0])

        self.assertEqual(
            {
                "library_id",
                "relative_path",
                "tape_relative_path",
                "size",
                "mtime_ns",
                "sha256",
            },
            set(parsed),
        )
        self.assertEqual(
            b'{"library_id":"LIB1","mtime_ns":123,"relative_path":"clip.mxf",'
            b'"sha256":"'
            + b"a" * 64
            + b'","size":4,"tape_relative_path":"libraries/LIB1/blocks/BLOCK4/files/clip.mxf"}\n',
            payload,
        )
        self.assertFalse(self.manifest_path.exists())

    def test_finalize_copies_closed_staging_manifest_then_writes_block_and_snapshot(
        self,
    ) -> None:
        """A finalization that omits an ordinary portable artifact breaks recovery."""
        self.writer.append(self.record)
        self._stage_record()

        self.writer.finalize(self.block)

        self.assertEqual(
            self.staging_path.read_bytes(), self.manifest_path.read_bytes()
        )
        self.assertEqual(
            {
                "format": "lto-library-backup-block-v1",
                "block_id": "BLOCK4",
                "library_id": "LIB1",
                "tape_id": "TAPE04",
                "completed_at": "2026-08-21T12:00:00+00:00",
                "file_count": 1,
                "total_bytes": 4,
                "copy_mode": "direct-files-no-tar",
                "sha256_recorded_during_source_stream": True,
            },
            json.loads(self.block_path.read_text(encoding="utf-8")),
        )
        self.assertTrue(self.snapshot_path.is_file())
        with closing(sqlite3.connect(self.snapshot_path)) as snapshot:
            self.assertEqual(
                str(SCHEMA_VERSION),
                snapshot.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )

    def test_finalize_snapshot_stays_anchored_after_host_path_substitution(
        self,
    ) -> None:
        self.writer.append(self.record)
        self._stage_record()
        anchored_host_state = self.root / "anchored-host-state"
        self.host_state.rename(anchored_host_state)
        attacker = self.root / "attacker-host-state"
        attacker.mkdir()
        self.host_state.symlink_to(attacker, target_is_directory=True)

        self.writer.finalize(self.block)

        self.assertTrue(self.snapshot_path.is_file())
        with closing(sqlite3.connect(self.snapshot_path)) as snapshot:
            self.assertEqual(
                "ok", snapshot.execute("PRAGMA integrity_check").fetchone()[0]
            )
        self.assertEqual([], list(attacker.iterdir()))
        self.assertEqual([], list(anchored_host_state.glob(".*.sqlite3")))

    def test_finalize_preserves_existing_manifest_and_stops_before_metadata_on_collision(
        self,
    ) -> None:
        """Replacing a tape manifest would make a completed block ambiguous."""
        self.writer.append(self.record)
        self._stage_record()
        self.manifest_path.parent.mkdir(parents=True)
        self.manifest_path.write_text("existing\n", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            self.writer.finalize(self.block)

        self.assertEqual("existing\n", self.manifest_path.read_text(encoding="utf-8"))
        self.assertFalse(self.block_path.exists())
        self.assertFalse(self.snapshot_path.exists())

    def test_finalize_stops_before_metadata_when_manifest_copy_fails(self) -> None:
        """Metadata after a partial manifest copy would advertise unavailable data."""
        self.writer.append(self.record)
        self._stage_record()

        with (
            patch(
                "ltobackup.tape.manifests.ManifestWriter._publish_staging_manifest",
                side_effect=OSError("injected copy failure"),
            ),
            self.assertRaisesRegex(OSError, "injected copy failure"),
        ):
            self.writer.finalize(self.block)

        self.assertFalse(self.manifest_path.exists())
        self.assertFalse(self.block_path.exists())
        self.assertFalse(self.snapshot_path.exists())

    def test_manifest_paths_reject_absolute_parent_traversal_and_backslashes(
        self,
    ) -> None:
        """Unsafe paths could escape the ordinary LTFS namespace."""
        for relative_path, tape_relative_path in (
            ("/clip.mxf", "libraries/LIB1/blocks/BLOCK4/files/clip.mxf"),
            ("../clip.mxf", "libraries/LIB1/blocks/BLOCK4/files/clip.mxf"),
            ("clip.mxf", "../files/clip.mxf"),
            ("clip\\mxf", "libraries/LIB1/blocks/BLOCK4/files/clip.mxf"),
        ):
            with self.assertRaises(ValidationError):
                FileManifestRecord(
                    "LIB1", relative_path, tape_relative_path, 4, 123, "a" * 64
                )

        self.assertFalse(self.staging_path.exists())

        with self.assertRaises(ValidationError):
            self.catalog.stage_file_version(
                "LIB1",
                "BLOCK4",
                "TAPE04",
                "folder//clip.mxf",
                "libraries/LIB1/blocks/BLOCK4/files/folder/clip.mxf",
                4,
                123,
                "a" * 64,
            )

    def test_writer_rejects_host_staging_beneath_the_ltfs_root(self) -> None:
        """A tape-resident JSONL staging file would keep a handle on LTFS per file."""
        with self.assertRaises(ValidationError):
            ManifestWriter(
                self.catalog,
                self.tape_root / ".lto-backup" / "staging" / "BLOCK4.jsonl",
                self.manifest_path,
                self.block_path,
                self.snapshot_path,
                tape_root=self.tape_root,
            )

    def test_writer_requires_a_tape_root_for_host_ltfs_separation(self) -> None:
        """An optional root lets callers silently place host staging on LTFS."""
        with self.assertRaises(ValidationError):
            ManifestWriter(
                self.catalog,
                self.staging_path,
                self.manifest_path,
                self.block_path,
                self.snapshot_path,
            )

    def test_copying_block_is_not_public_until_complete_blocks_promotes_it(
        self,
    ) -> None:
        """A copying block in public listings exposes provisional tape content."""
        self.assertEqual([], self.catalog.list_blocks("LIB1"))
        self._stage_record()
        self.assertEqual([], self.catalog.list_blocks("LIB1"))

        self.catalog.complete_blocks(["BLOCK4"])

        listed = self.catalog.list_blocks("LIB1")
        self.assertEqual(["BLOCK4"], [row["id"] for row in listed])
        self.assertEqual(1, listed[0]["visible"])

    def test_finalize_preflights_block_collision_before_publishing_manifest(
        self,
    ) -> None:
        """A pre-existing metadata target must retain its bytes and block publication."""
        self.writer.append(self.record)
        self._stage_record()
        self.block_path.parent.mkdir(parents=True)
        self.block_path.write_text("competitor", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            self.writer.finalize(self.block)

        self.assertEqual("competitor", self.block_path.read_text(encoding="utf-8"))
        self.assertFalse(self.manifest_path.exists())
        self.assertFalse(self.snapshot_path.exists())

    def test_finalize_rejects_staging_that_does_not_match_catalog_and_block(
        self,
    ) -> None:
        """Malformed or unbound staging must never become a portable tape receipt."""
        self.writer.append(
            FileManifestRecord(
                "LIB1",
                "other.mxf",
                "libraries/LIB1/blocks/BLOCK4/files/other.mxf",
                4,
                123,
                "b" * 64,
            )
        )
        self._stage_record()

        with self.assertRaises(ValidationError):
            self.writer.finalize(self.block)

        self.assertFalse(self.manifest_path.exists())
        self.assertFalse(self.block_path.exists())
        self.assertFalse(self.snapshot_path.exists())

    def test_source_name_may_be_nonportable_when_tape_path_is_portable(self) -> None:
        """Requiring source names to be Windows-safe would reject valid NFS files."""
        record = FileManifestRecord(
            "LIB1",
            "I Flintstones /episode.mkv",
            "libraries/LIB1/blocks/BLOCK4/files/~lto1~I Flintstones%20/episode.mkv",
            4,
            123,
            "a" * 64,
        )

        self.assertEqual("I Flintstones /episode.mkv", record.relative_path)

    def test_finalize_accepts_mapped_tape_path_for_nonportable_source_name(self) -> None:
        """Finalization must validate the mapped physical path, not the source name."""
        self.record = FileManifestRecord(
            "LIB1",
            "I Flintstones /episode.mkv",
            "libraries/LIB1/blocks/BLOCK4/files/~lto1~I Flintstones%20/episode.mkv",
            4,
            123,
            "a" * 64,
        )
        self.writer.append(self.record)
        self._stage_record()

        self.writer.finalize(self.block)

        self.assertTrue(self.manifest_path.is_file())
        self.assertTrue(self.block_path.is_file())

    def test_tape_path_still_rejects_windows_unsafe_names(self) -> None:
        """Relaxing the source field must not weaken the physical LTFS path."""
        for path in ("C:clip.mxf", "CON", "folder/AUX.txt", "clip. "):
            with self.assertRaises(ValidationError):
                FileManifestRecord(
                    "LIB1",
                    "source/clip.mxf",
                    path,
                    4,
                    123,
                    "a" * 64,
                )

    def test_finalize_publishes_validated_staging_bytes_after_in_place_mutation(
        self,
    ) -> None:
        """A mutable staging pathname must not become authority after validation."""
        self.writer.append(self.record)
        self._stage_record()
        expected = self.staging_path.read_bytes()
        original_preflight = self.writer._preflight_absent

        def mutate_after_preflight() -> None:
            original_preflight()
            self.staging_path.write_text('{"tampered":true}\n', encoding="utf-8")

        with patch.object(
            self.writer, "_preflight_absent", side_effect=mutate_after_preflight
        ):
            self.writer.finalize(self.block)

        self.assertEqual(expected, self.manifest_path.read_bytes())

    def test_oversized_block_manifest_is_rejected_before_ltfs_publication(self) -> None:
        """A payload above the publication bound must fail before any tape artifact."""
        self.writer.append(self.record)
        self._stage_record()
        with self.assertRaises(ValidationError):
            BlockManifest(
                "B" * 257,
                "LIB1",
                "TAPE04",
                "2026-08-21T12:00:00+00:00",
                1,
                4,
            )
        self.assertFalse(self.manifest_path.exists())
        self.assertFalse(self.block_path.exists())
        self.assertFalse(self.snapshot_path.exists())

    def test_close_is_idempotent_and_blocks_further_use(self) -> None:
        """Writer-owned directory descriptors must close deterministically."""
        self.writer.close()
        self.writer.close()
        with self.assertRaises(ValidationError):
            self.writer.append(self.record)

    def test_close_releases_writer_directory_descriptors(self) -> None:
        """A finished writer must not leak its host or LTFS directory descriptors."""
        before = len(list(Path("/proc/self/fd").iterdir()))
        writer = ManifestWriter(
            self.catalog,
            self.host_state / "second.manifest.jsonl",
            self.manifest_path,
            self.block_path,
            self.snapshot_path,
            tape_root=self.tape_root,
        )
        self.assertEqual(before + 2, len(list(Path("/proc/self/fd").iterdir())))
        writer.close()
        self.assertEqual(before, len(list(Path("/proc/self/fd").iterdir())))

    def test_append_preserves_staging_close_failure_without_retry_or_leak(self) -> None:
        """A close that reports failure after closing is ambiguous and must not retry."""
        original_close = os.close
        protected = {self.writer._host_fd, self.writer._tape_fd}
        calls: list[int] = []

        def close_then_fail(descriptor: int) -> None:
            calls.append(descriptor)
            original_close(descriptor)
            if descriptor not in protected:
                raise OSError("staging-close")

        with (
            patch("ltobackup.tape.manifests.os.close", side_effect=close_then_fail),
            self.assertRaisesRegex(OSError, "staging-close"),
        ):
            self.writer.append(self.record)

        staging_closes = [item for item in calls if item not in protected]
        self.assertEqual(1, len(staging_closes))
        with self.assertRaises(OSError) as closed:
            os.fstat(staging_closes[0])
        self.assertEqual(errno.EBADF, closed.exception.errno)
        for descriptor in protected:
            os.fstat(descriptor)

    def test_close_attempts_both_root_descriptors_once_and_notes_secondary_failure(
        self,
    ) -> None:
        """The first close error remains primary while later failures stay observable."""
        writer = ManifestWriter(
            self.catalog,
            self.host_state / "close.manifest.jsonl",
            self.manifest_path,
            self.block_path,
            self.snapshot_path,
            tape_root=self.tape_root,
        )
        self.addCleanup(writer.close)
        original_close = os.close
        tape_fd, host_fd = writer._tape_fd, writer._host_fd
        calls: list[int] = []

        def close_then_fail(descriptor: int) -> None:
            calls.append(descriptor)
            original_close(descriptor)
            if descriptor == tape_fd:
                raise OSError("tape-root-close")
            if descriptor == host_fd:
                raise OSError("host-parent-close")

        before = len(list(Path("/proc/self/fd").iterdir()))
        with (
            patch("ltobackup.tape.manifests.os.close", side_effect=close_then_fail),
            self.assertRaisesRegex(OSError, "tape-root-close") as raised,
        ):
            writer.close()

        self.assertEqual(before - 2, len(list(Path("/proc/self/fd").iterdir())))
        self.assertEqual([tape_fd, host_fd], calls)
        self.assertIn(
            "host-parent-close", "\n".join(getattr(raised.exception, "__notes__", []))
        )
        writer.close()
        with self.assertRaises(ValidationError):
            writer.append(self.record)

    def test_publish_bytes_retries_short_writes_and_eintr_without_partial_publication(
        self,
    ) -> None:
        """The host source must contain every validated byte before tape publication."""
        original_write = os.write
        writes = 0

        def short_then_full(descriptor: int, data) -> int:
            nonlocal writes
            writes += 1
            if writes == 1:
                raise OSError(errno.EINTR, "interrupted")
            if writes == 2:
                return original_write(descriptor, data[:2])
            return original_write(descriptor, data)

        with patch("ltobackup.tape.manifests.os.write", side_effect=short_then_full):
            self.writer._publish_bytes(b"abcdef", self.writer._manifest_relative)

        self.assertEqual(b"abcdef", self.manifest_path.read_bytes())

    def test_publish_bytes_does_not_require_ltfs_hard_link_support(self) -> None:
        """LTFS implements rename but deliberately returns ENOSYS for link(2)."""
        with patch(
            "ltobackup.tape.manifests.os.link",
            side_effect=OSError(errno.ENOSYS, "hard links unsupported"),
        ):
            self.writer._publish_bytes(b"abcdef", self.writer._manifest_relative)

        self.assertEqual(b"abcdef", self.manifest_path.read_bytes())

    def test_publish_bytes_does_not_require_memfd_write_access(self) -> None:
        """The confined qualification domain may not write anonymous memfd files."""
        with patch(
            "ltobackup.tape.manifests.os.memfd_create",
            side_effect=PermissionError(errno.EACCES, "SELinux denied memfd write"),
        ):
            self.writer._publish_bytes(b"abcdef", self.writer._manifest_relative)

        self.assertEqual(b"abcdef", self.manifest_path.read_bytes())

    def test_publish_bytes_rejects_zero_or_invalid_short_write_before_publication(
        self,
    ) -> None:
        """A non-progressing writer must fail before the tape destination exists."""
        for result in (0, 7):
            with self.subTest(result=result):
                with (
                    patch("ltobackup.tape.manifests.os.write", return_value=result),
                    self.assertRaisesRegex(OSError, "scrittura staging incompleta"),
                ):
                    self.writer._publish_bytes(
                        b"abcdef", self.writer._manifest_relative
                    )
                self.assertFalse(self.manifest_path.exists())

    def test_publish_bytes_preserves_write_error_when_source_close_fails(self) -> None:
        """Ambiguous close failure cannot mask a non-progressing source write."""
        original_close = os.close
        close_calls: list[int] = []
        write_calls = 0

        def zero_write(descriptor: int, data) -> int:
            nonlocal write_calls
            write_calls += 1
            return 0

        def close_then_fail(descriptor: int) -> None:
            close_calls.append(descriptor)
            original_close(descriptor)
            raise OSError("source-close")

        before = len(list(Path("/proc/self/fd").iterdir()))
        with (
            patch("ltobackup.tape.manifests.os.write", side_effect=zero_write),
            patch("ltobackup.tape.manifests.os.close", side_effect=close_then_fail),
            self.assertRaises(OSError) as raised,
        ):
            self.writer._publish_bytes(b"abcdef", self.writer._manifest_relative)

        self.assertEqual(("scrittura staging incompleta",), raised.exception.args)
        self.assertEqual(
            ["secondary manifest source cleanup failure: OSError: source-close"],
            getattr(raised.exception, "__notes__", []),
        )
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertEqual(1, write_calls)
        self.assertEqual(1, len(close_calls))
        self.assertEqual(before, len(list(Path("/proc/self/fd").iterdir())))

    def test_publish_bytes_preserves_publisher_error_when_source_close_fails(
        self,
    ) -> None:
        """Source cleanup cannot replace an exact publisher exception object."""
        original_close = os.close
        close_calls: list[int] = []
        primary = ValidationError("publish-primary")

        def close_then_fail(descriptor: int) -> None:
            close_calls.append(descriptor)
            original_close(descriptor)
            raise OSError("source-close")

        before = len(list(Path("/proc/self/fd").iterdir()))
        with (
            patch.object(self.writer, "_publish_from_fd", side_effect=primary),
            patch("ltobackup.tape.manifests.os.close", side_effect=close_then_fail),
            self.assertRaises(ValidationError) as raised,
        ):
            self.writer._publish_bytes(b"abcdef", self.writer._manifest_relative)

        self.assertIs(primary, raised.exception)
        self.assertEqual(
            ["secondary manifest source cleanup failure: OSError: source-close"],
            getattr(raised.exception, "__notes__", []),
        )
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertEqual(1, len(close_calls))
        # A full-suite worker can close unrelated descriptors concurrently; a
        # decrease is not a leak. The equality above proves the owned source was
        # closed exactly once.
        self.assertLessEqual(len(list(Path("/proc/self/fd").iterdir())), before)

    def test_publish_bytes_raises_source_close_error_without_primary_error(self) -> None:
        """A lone ambiguous close failure remains the outward exception."""
        original_close = os.close
        close_calls: list[int] = []

        def close_then_fail(descriptor: int) -> None:
            close_calls.append(descriptor)
            original_close(descriptor)
            raise OSError("source-close")

        before = len(list(Path("/proc/self/fd").iterdir()))
        with (
            patch.object(self.writer, "_publish_from_fd"),
            patch("ltobackup.tape.manifests.os.close", side_effect=close_then_fail),
            self.assertRaisesRegex(OSError, "source-close") as raised,
        ):
            self.writer._publish_bytes(b"abcdef", self.writer._manifest_relative)

        self.assertEqual([], getattr(raised.exception, "__notes__", []))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertEqual(1, len(close_calls))
        self.assertEqual(before, len(list(Path("/proc/self/fd").iterdir())))

    def test_context_body_error_preserves_ordered_root_close_failures(self) -> None:
        """Cleanup cannot replace the body exception or hide a second close failure."""
        writer = ManifestWriter(
            self.catalog,
            self.host_state / "context.manifest.jsonl",
            self.manifest_path,
            self.block_path,
            self.snapshot_path,
            tape_root=self.tape_root,
        )
        original_close = os.close
        tape_fd, host_fd = writer._tape_fd, writer._host_fd

        def close_then_fail(descriptor: int) -> None:
            original_close(descriptor)
            if descriptor == tape_fd:
                raise OSError("tape-close")
            if descriptor == host_fd:
                raise OSError("host-close")

        with (
            patch("ltobackup.tape.manifests.os.close", side_effect=close_then_fail),
            self.assertRaisesRegex(RuntimeError, "body") as raised,
            writer,
        ):
            raise RuntimeError("body")

        notes = "\n".join(getattr(raised.exception, "__notes__", []))
        self.assertIn("tape-close", notes)
        self.assertIn("host-close", notes)

    def test_context_success_raises_first_close_and_notes_second(self) -> None:
        writer = ManifestWriter(
            self.catalog,
            self.host_state / "context-success.manifest.jsonl",
            self.manifest_path,
            self.block_path,
            self.snapshot_path,
            tape_root=self.tape_root,
        )
        original_close = os.close
        tape_fd, host_fd = writer._tape_fd, writer._host_fd

        def close_then_fail(descriptor: int) -> None:
            original_close(descriptor)
            if descriptor == tape_fd:
                raise OSError("tape-close")
            if descriptor == host_fd:
                raise OSError("host-close")

        with (
            patch("ltobackup.tape.manifests.os.close", side_effect=close_then_fail),
            self.assertRaisesRegex(OSError, "tape-close") as raised,
            writer,
        ):
            pass
        self.assertIn("host-close", "\n".join(raised.exception.__notes__))

    def test_constructor_cleanup_boundaries_close_once_and_preserve_error(self) -> None:
        """Every post-host-open failure closes descriptors exactly once with notes."""
        original_open, original_fstat, original_close = os.open, os.fstat, os.close
        scenarios = ("tape-open", "host-fstat", "tape-fstat", "containment")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                opened: list[int] = []
                closed: list[int] = []
                fstats = [0]

                def tracked_open(path, flags, *args, scenario=scenario, opened=opened):
                    if scenario == "tape-open" and len(opened) == 1:
                        raise OSError("primary-tape-open")
                    descriptor = original_open(path, flags, *args)
                    opened.append(descriptor)
                    return descriptor

                def tracked_fstat(descriptor: int, scenario=scenario, fstats=fstats):
                    fstats[0] += 1
                    if scenario == "host-fstat" and fstats[0] == 1:
                        raise OSError("primary-host-fstat")
                    if scenario == "tape-fstat" and fstats[0] == 2:
                        raise OSError("primary-tape-fstat")
                    return original_fstat(descriptor)

                def close_then_fail(descriptor: int, closed=closed) -> None:
                    closed.append(descriptor)
                    original_close(descriptor)
                    raise OSError(f"close-{descriptor}")

                staging = self.host_state / f"{scenario}.jsonl"
                if scenario == "containment":
                    staging = self.tape_root / "invalid.jsonl"
                before = len(list(Path("/proc/self/fd").iterdir()))
                with (
                    patch("ltobackup.tape.manifests.os.open", side_effect=tracked_open),
                    patch(
                        "ltobackup.tape.manifests.os.fstat", side_effect=tracked_fstat
                    ),
                    patch(
                        "ltobackup.tape.manifests.os.close", side_effect=close_then_fail
                    ),
                    self.assertRaises(
                        OSError if scenario.endswith("fstat") else ValidationError
                    ) as raised,
                ):
                    ManifestWriter(
                        self.catalog,
                        staging,
                        self.manifest_path,
                        self.block_path,
                        self.snapshot_path,
                        tape_root=self.tape_root,
                    )
                self.assertEqual(before, len(list(Path("/proc/self/fd").iterdir())))
                self.assertEqual(list(reversed(opened)), closed)
                if scenario == "tape-open":
                    self.assertEqual(
                        "primary-tape-open", str(raised.exception.__cause__)
                    )
                elif scenario.endswith("fstat"):
                    self.assertEqual(f"primary-{scenario}", str(raised.exception))
                else:
                    self.assertIn("fuori da LTFS", str(raised.exception))
                notes = "\n".join(getattr(raised.exception, "__notes__", []))
                self.assertIn("close-", notes)

    def test_staged_file_is_not_latest_until_block_commit(self) -> None:
        """A visible staged row would expose data before a successful unmount."""
        version_id = self.catalog.stage_file_version(
            "LIB1",
            "BLOCK4",
            "TAPE04",
            "clip.mxf",
            "libraries/LIB1/blocks/BLOCK4/files/clip.mxf",
            4,
            123,
            "a" * 64,
        )

        self.assertNotIn("clip.mxf", self.catalog.latest_versions("LIB1"))
        self.assertEqual(
            0,
            self.catalog.connection.execute(
                "SELECT visible FROM file_versions WHERE id=?", (version_id,)
            ).fetchone()[0],
        )
        self.catalog.complete_blocks(["BLOCK4"])

        self.assertIn("clip.mxf", self.catalog.latest_versions("LIB1"))
        self.assertEqual(
            1,
            self.catalog.connection.execute(
                "SELECT visible FROM file_versions WHERE id=?", (version_id,)
            ).fetchone()[0],
        )

    def _stage_record(self) -> int:
        return self.catalog.stage_file_version(
            self.record.library_id,
            "BLOCK4",
            "TAPE04",
            self.record.relative_path,
            self.record.tape_relative_path,
            self.record.size,
            self.record.mtime_ns,
            self.record.sha256,
        )

    def test_complete_blocks_rolls_back_status_and_visibility_together(self) -> None:
        """A partial catalog commit must not reveal one block from a failed batch."""
        self.catalog.stage_file_version(
            "LIB1",
            "BLOCK4",
            "TAPE04",
            "clip.mxf",
            "libraries/LIB1/blocks/BLOCK4/files/clip.mxf",
            4,
            123,
            "a" * 64,
        )

        with self.assertRaisesRegex(Exception, "Blocco non in stato copying"):
            self.catalog.complete_blocks(["BLOCK4", "MISSING"])

        block = self.catalog.list_blocks("LIB1", include_forgotten=True)[0]
        self.assertEqual("copying", block["status"])
        self.assertEqual(0, block["visible"])
        self.assertEqual([], self.catalog.list_blocks("LIB1"))
        self.assertEqual({}, self.catalog.latest_versions("LIB1"))
        self.assertEqual(
            0,
            self.catalog.connection.execute(
                "SELECT visible FROM file_versions WHERE block_id='BLOCK4'"
            ).fetchone()[0],
        )


if __name__ == "__main__":
    unittest.main()
