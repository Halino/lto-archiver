"""Storage reads are bounded metadata observations, never catalog scans."""

from __future__ import annotations

import importlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from httpx2 import ASGITransport, AsyncClient

from ltobackup.catalog import Catalog
from ltobackup.daemon.api import create_app
from ltobackup.daemon.backups import BackupManager
from ltobackup.daemon.events import EventBus
from ltobackup.daemon.service import DaemonService, Principal
from ltobackup.linux_settings import LinuxPaths, LinuxSettings


class StorageMonitorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.catalog = self.root / "catalog.db"
        self.catalog.write_bytes(b"catalog bytes")
        self.wal = self.root / "catalog.db-wal"
        self.wal.write_bytes(b"12345")

    def monitor(self, **kwargs):
        name = "ltobackup.daemon.storage"
        self.assertIsNotNone(importlib.util.find_spec(name), "storage monitor is missing")
        return importlib.import_module(name).StorageMonitor(
            catalog_path=self.catalog,
            storage_paths={"state": self.root, "backups": self.root, "scratch": self.root},
            **kwargs,
        )

    def test_reports_real_file_sizes_and_shared_filesystem_without_reading_contents(self):
        monitor = self.monitor()
        with (
            patch("sqlite3.connect", side_effect=AssertionError("must not open catalog")),
            patch.object(Path, "iterdir", side_effect=AssertionError("must not scan directories")),
            patch.object(Path, "glob", side_effect=AssertionError("must not scan directories")),
            patch.object(Path, "read_bytes", side_effect=AssertionError("must not read contents")),
        ):
            summary = monitor.snapshot()
        self.assertEqual(13, summary.catalog_bytes)
        self.assertEqual(5, summary.wal_bytes)
        self.assertEqual(1, len(summary.filesystems))
        filesystem = summary.filesystems[0]
        self.assertEqual({"state", "backups", "scratch"}, set(filesystem.roles))
        self.assertGreater(filesystem.total_bytes, 0)
        self.assertGreaterEqual(filesystem.available_bytes, 0)
        self.assertLessEqual(filesystem.available_bytes, filesystem.total_bytes)
        self.assertEqual("unknown", summary.rollback_status)
        self.assertNotIn(str(self.root), summary.model_dump_json())

    def test_cache_holds_one_sample_until_expiry_then_refreshes(self):
        now = [0.0]
        monitor = self.monitor(clock=lambda: now[0])
        self.assertEqual(13, monitor.snapshot().catalog_bytes)
        self.catalog.write_bytes(b"a" * 26)
        now[0] = 14.0
        self.assertEqual(13, monitor.snapshot().catalog_bytes)
        now[0] = 16.0
        self.assertEqual(26, monitor.snapshot().catalog_bytes)

    def test_missing_wal_is_zero_but_missing_catalog_is_unknown(self):
        self.wal.unlink()
        self.catalog.unlink()
        summary = self.monitor().snapshot()
        self.assertIsNone(summary.catalog_bytes)
        self.assertEqual(0, summary.wal_bytes)

    def test_filesystem_probe_failure_reports_unknown_without_losing_catalog_sizes(self):
        monitor = self.monitor()
        with patch("os.statvfs", side_effect=PermissionError("private path")):
            summary = monitor.snapshot()
        self.assertEqual(13, summary.catalog_bytes)
        self.assertTrue(summary.filesystems)
        self.assertTrue(all(row.available_bytes is None for row in summary.filesystems))
        self.assertTrue(all(row.total_bytes is None for row in summary.filesystems))


class StorageApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        settings = LinuxSettings(
            state_dir=root / "state",
            socket_path=root / "run" / "daemon.sock",
            source_roots=(root / "source",),
            restore_roots=(root / "restore",),
        )
        settings.source_roots[0].mkdir(parents=True)
        self.paths = LinuxPaths.from_settings(settings)
        backups = BackupManager(self.paths.catalog_file, self.paths.backup_dir)
        backups.prepare_and_initialize()
        service = DaemonService(
            self.paths,
            settings,
            backups,
            None,
            EventBus(lambda: Catalog(self.paths.catalog_file)),
        )
        self.app = create_app(service)
        self.app.dependency_overrides[
            service.principals.require_mutation_principal
        ] = lambda: Principal("synthetic-admin")
        self.client = AsyncClient(
            transport=ASGITransport(app=self.app),
            base_url="http://testserver",
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_authorized_read_reports_catalog_and_unknown_rollback(self):
        response = await self.client.get("/api/v1/storage")
        self.assertEqual(200, response.status_code, response.text)
        payload = response.json()
        self.assertGreater(payload["catalog_bytes"], 0)
        self.assertEqual("unknown", payload["rollback_status"])
        self.assertEqual({"state", "backups", "scratch"}, {
            role for row in payload["filesystems"] for role in row["roles"]
        })
        self.assertNotIn(str(self.paths.state_dir), response.text)

    async def test_untrusted_request_cannot_read_storage(self):
        self.app.dependency_overrides.clear()
        response = await self.client.get("/api/v1/storage")
        self.assertEqual(403, response.status_code, response.text)
