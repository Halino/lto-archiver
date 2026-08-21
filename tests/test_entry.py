from __future__ import annotations

import contextlib
import io
import json
import runpy
import sys
import unittest
from unittest.mock import patch


class EntryPointTests(unittest.TestCase):
    def test_internal_tape_serial_probe_uses_requested_device(self) -> None:
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["lto_backup_entry.py", "--internal-tape-serial", "TAPE7"]),
            patch(
                "ltobackup.automation.WindowsTapeDevice.read_unit_serial",
                return_value="DRIVE-SERIAL-42",
            ) as read_serial,
            contextlib.redirect_stdout(output),
        ):
            with self.assertRaises(SystemExit) as exit_status:
                runpy.run_module("lto_backup_entry", run_name="__main__")

        self.assertEqual(0, exit_status.exception.code)
        self.assertEqual(
            {"device_name": "TAPE7", "serial_number": "DRIVE-SERIAL-42"},
            json.loads(output.getvalue()),
        )
        read_serial.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
