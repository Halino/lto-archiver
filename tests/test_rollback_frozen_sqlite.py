"""Frozen rollback verification must never open its originals with SQLite."""

import hashlib
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.test_rhel9_rollback import _load_module


class FrozenRollbackSqliteTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lto-frozen-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.module = _load_module()
        self.host = self.module.SystemRollbackHost()
        # Host free-space observation is the only simulated resource; all DB,
        # WAL, SHM, copies, metadata and SQLite validation remain real.
        capacity = mock.patch.object(self.module.os, "statvfs", return_value=
                                     SimpleNamespace(f_bavail=100 * 1024**3, f_frsize=1))
        capacity.start()
        self.addCleanup(capacity.stop)

    def frozen_catalog(self, *, pending=False, shm=True):
        source = self.root / "source.db"
        target = self.root / "snapshots/application_state/catalog.db"
        target.parent.mkdir(parents=True)
        writer = sqlite3.connect(source)
        try:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)")
            writer.execute("INSERT INTO metadata VALUES('schema_version',?)",
                           ("39" if pending else "40",))
            writer.commit()
            writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            if pending:
                writer.execute("UPDATE metadata SET value='40'")
                writer.commit()
            for suffix in ("", "-wal", "-shm") if shm else ("", "-wal"):
                shutil.copy2(Path(str(source) + suffix), Path(str(target) + suffix))
        finally:
            writer.close()
        return target

    @staticmethod
    def evidence(root):
        result = {}
        for path in (root, *sorted(root.rglob("*"))):
            st = path.lstat()
            result[str(path.relative_to(root))] = (
                st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
                st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
            )
        return result

    def verify_catalog_preserved(self, *, pending=False, shm=True):
        path = self.frozen_catalog(pending=pending, shm=shm)
        snapshots = path.parent.parent
        before = self.evidence(snapshots)
        result = {row.identity: row for row in self.host.check_copied_state(snapshots)}
        self.assertTrue(result["catalog"].schema_ok)
        self.assertEqual(before, self.evidence(snapshots))

    def test_copied_catalog_validation_preserves_empty_wal_and_shm_metadata(self):
        self.verify_catalog_preserved()

    def test_copied_catalog_validation_includes_pending_wal_without_mutating_it(self):
        self.verify_catalog_preserved(pending=True)

    def test_copied_catalog_validation_does_not_create_missing_shm(self):
        self.verify_catalog_preserved(pending=True, shm=False)

    def test_frozen_validation_rejects_wrong_schema_and_corruption(self):
        path = self.frozen_catalog(pending=True)
        wal = Path(str(path) + "-wal")
        wal.unlink()  # The main file alone is schema39, not the committed40.
        self.assertFalse(self.host._sqlite_check(path, catalog=True, frozen=True))
        path.write_bytes(b"invalid sqlite")
        self.assertFalse(self.host._sqlite_check(path, catalog=True, frozen=True))

    def test_frozen_validation_rejects_symlinks_and_hardlinks(self):
        path = self.frozen_catalog()
        wal = Path(str(path) + "-wal")
        wal.unlink()
        unrelated = self.root / "unrelated"
        unrelated.write_bytes(b"protected")
        wal.symlink_to(unrelated)
        self.assertFalse(self.host._sqlite_check(path, catalog=True, frozen=True))
        self.assertEqual(b"protected", unrelated.read_bytes())
        wal.unlink()
        os.link(path, self.root / "alias")
        self.assertFalse(self.host._sqlite_check(path, catalog=True, frozen=True))

    def test_insufficient_scratch_refuses_before_copy_and_preserves_originals(self):
        path = self.frozen_catalog(pending=True)
        before = self.evidence(path.parent)
        scratch = self.root / "scratch"
        scratch.mkdir()
        real_temporary = tempfile.TemporaryDirectory
        with (
            mock.patch.object(self.module.os, "statvfs", return_value=
                              SimpleNamespace(f_bavail=10 * 1024**3, f_frsize=1)),
            mock.patch.object(self.module.tempfile, "TemporaryDirectory",
                              side_effect=lambda **kw: real_temporary(dir=scratch, **kw)),
        ):
            self.assertFalse(self.host._sqlite_check(path, catalog=True, frozen=True))
        self.assertEqual(before, self.evidence(path.parent))
        self.assertEqual([], list(scratch.iterdir()))

    def test_validation_uses_one_family_copy_and_never_connects_to_original(self):
        path = self.frozen_catalog(pending=True)
        source_size = path.stat().st_size + Path(str(path) + "-wal").stat().st_size
        scratch = self.root / "scratch"
        scratch.mkdir()
        real_temporary, real_connect = tempfile.TemporaryDirectory, sqlite3.connect
        observed = []

        def connect(database, *args, **kwargs):
            self.assertNotIn(str(path), str(database))
            observed.append(sum(p.stat().st_size for p in scratch.rglob("*") if p.is_file()))
            return real_connect(database, *args, **kwargs)

        with (
            mock.patch.object(self.module.tempfile, "TemporaryDirectory",
                              side_effect=lambda **kw: real_temporary(dir=scratch, **kw)),
            mock.patch.object(self.module.sqlite3, "connect", side_effect=connect),
        ):
            self.assertTrue(self.host._sqlite_check(path, catalog=True, frozen=True))
        self.assertEqual([source_size], observed)
        self.assertEqual([], list(scratch.iterdir()))

    def test_source_changes_during_copy_are_rejected(self):
        path = self.frozen_catalog(pending=True)
        real_read = self.module.os.read
        changed = []

        def read(fd, count):
            data = real_read(fd, count)
            if not changed:
                changed.append(True)
                os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1000000))
            return data

        with mock.patch.object(self.module.os, "read", side_effect=read):
            self.assertFalse(self.host._sqlite_check(path, catalog=True, frozen=True))
        self.assertTrue(changed)

    def test_sidecar_appearing_during_copy_is_rejected(self):
        path = self.frozen_catalog(pending=True, shm=False)
        real_read = self.module.os.read
        changed = []

        def read(fd, count):
            data = real_read(fd, count)
            if not changed:
                changed.append(True)
                Path(str(path) + "-shm").write_bytes(b"foreign writer")
            return data

        with mock.patch.object(self.module.os, "read", side_effect=read):
            self.assertFalse(self.host._sqlite_check(path, catalog=True, frozen=True))
        self.assertTrue(changed)

    def test_interrupted_copy_removes_scratch_without_changing_originals(self):
        path = self.frozen_catalog(pending=True)
        before = self.evidence(path.parent)
        scratch = self.root / "scratch"
        scratch.mkdir()
        real_temporary = tempfile.TemporaryDirectory
        with (
            mock.patch.object(self.module.tempfile, "TemporaryDirectory",
                              side_effect=lambda **kw: real_temporary(dir=scratch, **kw)),
            mock.patch.object(self.module.os, "read", side_effect=OSError("read interrupted")),
        ):
            self.assertFalse(self.host._sqlite_check(path, catalog=True, frozen=True))
        self.assertEqual(before, self.evidence(path.parent))
        self.assertEqual([], list(scratch.iterdir()))

    def test_auth_and_broker_copies_preserve_wal_sidecars(self):
        for name, version in (("auth", 2), ("broker", 10)):
            with self.subTest(name=name):
                source = self.root / (name + ".db")
                target = self.root / name / "state.db"
                target.parent.mkdir()
                writer = sqlite3.connect(source)
                try:
                    writer.execute("PRAGMA journal_mode=WAL")
                    writer.execute(f"PRAGMA user_version={version}")
                    for table in (("web_users", "web_sessions", "web_auth_audit", "web_idempotency")
                                  if name == "auth" else ("fixture",)):
                        writer.execute(f"CREATE TABLE {table}(id INTEGER PRIMARY KEY)")
                    writer.commit()
                    for suffix in ("", "-wal", "-shm"):
                        shutil.copy2(Path(str(source) + suffix), Path(str(target) + suffix))
                finally:
                    writer.close()
                before = self.evidence(target.parent)
                self.assertTrue(self.host._sqlite_check(target, frozen=True, **{name: True}))
                self.assertEqual(before, self.evidence(target.parent))


if __name__ == "__main__":
    unittest.main()
