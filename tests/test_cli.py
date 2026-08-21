import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ltobackup.automation import TapeTelemetrySnapshot
from ltobackup.cli import build_parser, handle
from ltobackup.errors import CopyError
from ltobackup.settings import AppPaths


class CliTelemetryTests(unittest.TestCase):
    def test_read_only_telemetry_does_not_require_catalog_or_job_lock(self) -> None:
        args = build_parser().parse_args(["--json", "telemetry", "--device", "TAPE9"])
        snapshot = TapeTelemetrySnapshot(
            available=True,
            partition=1,
            first_logical_object=42,
            buffered_bytes=1024,
        )
        with tempfile.TemporaryDirectory() as temporary, patch(
            "ltobackup.cli.WindowsTapeDevice.read_telemetry", return_value=snapshot
        ):
            result = handle(AppPaths(Path(temporary)), args)

        self.assertTrue(result["read_only"])
        self.assertEqual("TAPE9", result["device"])
        self.assertEqual("buffered", result["activity"])
        self.assertEqual(42, result["first_logical_object"])

    def test_read_only_telemetry_reports_exclusive_drive_as_unavailable(self) -> None:
        args = build_parser().parse_args(["telemetry"])
        with tempfile.TemporaryDirectory() as temporary, patch(
            "ltobackup.cli.WindowsTapeDevice.read_telemetry",
            side_effect=CopyError("drive riservato"),
        ):
            result = handle(AppPaths(Path(temporary)), args)

        self.assertEqual("unavailable", result["activity"])
        self.assertIn("riservato", result["detail"])


if __name__ == "__main__":
    unittest.main()
