"""Dashboard storage values come from the daemon, with an honest fallback."""

from __future__ import annotations

import importlib

from ltobackup.client import DaemonUnavailable
from tests.web.test_dashboard import WebAppTestCase


class StorageDashboardTests(WebAppTestCase):
    def storage(self, **_kwargs):
        models = importlib.import_module("ltobackup.daemon.api_models")
        return models.StorageSummaryV1(
            measured_at="2026-09-13T12:00:00Z",
            cache_seconds=15,
            filesystems=({
                "roles": ("state", "backups", "scratch"),
                "total_bytes": 21474836480,
                "available_bytes": 10737418240,
            },),
            catalog_bytes=2147483648,
            wal_bytes=1048576,
            rollback_status="unknown",
        )

    def test_dashboard_and_fragment_show_storage_without_inventing_rollback(self):
        self.daemon.get_storage_summary = self.storage
        self.login()
        for path in ("/", "/status-fragment"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(200, response.status_code)
                self.assertIn('id="storage-title"', response.text)
                self.assertIn("10.00 GiB", response.text)
                self.assertIn("20.00 GiB", response.text)
                self.assertIn("2.00 GiB", response.text)
                self.assertIn("1.00 MiB", response.text)
                self.assertIn("Rollback backup", response.text)
                self.assertIn("Not available", response.text)
                self.assertIn('data-live-key="storage"', response.text)
        self.assertEqual([], self.daemon.mutations)

    def test_storage_outage_keeps_operation_dashboard_available(self):
        def unavailable(**_kwargs):
            raise DaemonUnavailable()

        self.daemon.get_storage_summary = unavailable
        self.login()
        response = self.client.get("/status-fragment")
        self.assertEqual(200, response.status_code)
        self.assertIn('id="storage-title"', response.text)
        self.assertIn("Storage information is not available", response.text)
        self.assertIn("Files completed", response.text)
        self.assertNotIn("0.00 GiB", response.text)
