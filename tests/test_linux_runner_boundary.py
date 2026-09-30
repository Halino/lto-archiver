from __future__ import annotations

import importlib.util
import inspect
import unittest
from pathlib import Path

import ltobackup.automation as automation
from ltobackup.application import LtoApplication
from ltobackup.settings import AppPaths, Settings


class LinuxRunnerBoundaryTests(unittest.TestCase):
    def test_legacy_windows_runtime_modules_are_not_importable(self) -> None:
        for module_name in (
            "ltobackup.__main__",
            "ltobackup.cli",
            "ltobackup.legacy_guard",
            "ltobackup.security",
        ):
            with self.subTest(module=module_name):
                self.assertIsNone(importlib.util.find_spec(module_name))

    def test_automation_exposes_no_windows_controller_or_telemetry_runtime(self) -> None:
        for name in (
            "StoreOpenInterface",
            "StoreOpenMapping",
            "StoreOpenPlatform",
            "WindowsStoreOpenPlatform",
            "WindowsStoreOpenMappingService",
            "StoreOpenController",
            "WindowsTapeDevice",
            "TapePosition",
            "TapeTelemetrySnapshot",
            "TapeTelemetryMonitor",
            "choose_mount_path",
            "classify_tape_activity",
            "parse_unit_serial_vpd",
            "parse_read_position_short",
            "parse_log_sense_parameters",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(automation, name))

    def test_neutral_tape_controller_has_only_the_runner_lifecycle(self) -> None:
        controller_type = getattr(automation, "TapeController", None)
        self.assertIsNotNone(controller_type)
        self.assertEqual(
            {
                "format",
                "mount",
                "unmount_and_eject",
                "wait_for_media",
            },
            {
                name
                for name, value in vars(controller_type).items()
                if callable(value) and not name.startswith("_")
            },
        )

    def test_automatic_runner_requires_an_explicit_controller(self) -> None:
        signature = inspect.signature(automation.AutomaticJobRunner)
        self.assertNotIn("storeopen", signature.parameters)
        controller_parameter = signature.parameters["controller"]
        self.assertEqual(inspect.Parameter.KEYWORD_ONLY, controller_parameter.kind)
        self.assertIs(inspect.Parameter.empty, controller_parameter.default)

        controller = object()
        runner = automation.AutomaticJobRunner(
            AppPaths(Path("/not-used")),
            Settings(),
            controller=controller,
            backup=lambda *_args: {},
        )
        self.assertIs(controller, runner.controller)

    def test_application_has_no_legacy_default_controller_runner(self) -> None:
        self.assertFalse(hasattr(LtoApplication, "run_automatic_job"))


if __name__ == "__main__":
    unittest.main()
