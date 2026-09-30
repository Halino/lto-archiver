"""A first public install must not reuse an LTO host or alter it during admission."""

from __future__ import annotations

import json
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


TOOL = Path(__file__).resolve().parents[1] / "packaging/rpm/check-public-fresh-host.py"


class FreshHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = runpy.run_path(str(TOOL))

    def test_fresh_host_rejects_old_package_or_state_without_mutation(self) -> None:
        state = self.gate["HostState"]
        evaluate = self.gate["evaluate_fresh_host"]
        cases = (
            (state(("lto-archiver-0.11.27-144.el9.noarch",), (), ()),
             "installed LTO package: lto-archiver-0.11.27-144.el9.noarch"),
            (state((), ("/var/lib/lto-archiver/catalog.db",), ()),
             "existing LTO path: /var/lib/lto-archiver/catalog.db"),
            (state((), ("/etc/lto-archiver/credentials",), ()),
             "existing LTO path: /etc/lto-archiver/credentials"),
            (state((), (), ("lto-archiverd.socket (inactive)",)),
             "managed LTO unit: lto-archiverd.socket (inactive)"),
        )
        for observed, reason in cases:
            with self.subTest(reason=reason):
                self.assertEqual(evaluate(observed), (reason,))

        self.assertEqual(evaluate(state((), (), ())), ())
        self.assertEqual(
            evaluate(state(("z", "a"), ("/z", "/a"), ("z.service", "a.service"))),
            tuple(sorted((
                "installed LTO package: z", "installed LTO package: a",
                "existing LTO path: /z", "existing LTO path: /a",
                "managed LTO unit: z.service", "managed LTO unit: a.service",
            ))),
        )

    def test_collector_catches_dangling_state_and_inactive_unit_read_only(self) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(command: list[str]) -> bytes:
            calls.append(tuple(command))
            if command[0] == "rpm":
                return b"lto-ltfs 0.1.0-21.el9.x86_64\n"
            if "list-unit-files" in command:
                return b"lto-archiverd.socket disabled\n"
            if "list-units" in command:
                return b""
            if "show" in command:
                return (b"Id=lto-archiverd.socket\nLoadState=loaded\n"
                        b"ActiveState=inactive\nUnitFileState=disabled\n")
            raise AssertionError(command)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "etc/lto-archiver").mkdir(parents=True)
            (root / "var/lib").mkdir(parents=True)
            (root / "var/lib/lto-archiver").symlink_to("missing-catalog")
            observed = self.gate["collect_host_state"](root=root, runner=runner)
        reasons = self.gate["evaluate_fresh_host"](observed)
        self.assertIn("existing LTO path: /var/lib/lto-archiver", reasons)
        self.assertIn("existing LTO path: /etc/lto-archiver", reasons)
        self.assertIn("installed LTO package: lto-ltfs-0.1.0-21.el9.x86_64", reasons)
        self.assertIn("managed LTO unit: lto-archiverd.socket (load=loaded, active=inactive, file=disabled)", reasons)
        self.assertTrue(all(command[0] in {"rpm", "systemctl"} for command in calls))
        self.assertTrue(all(not set(command) & {"install", "erase", "start", "stop", "unmask"} for command in calls))

    def test_json_output_is_refusal_not_success_for_existing_state(self) -> None:
        state = self.gate["HostState"]((), ("/etc/lto-archiver",), ())
        with patch.dict(self.gate["main"].__globals__, {"collect_host_state": lambda: state}):
            with patch("builtins.print") as printed:
                self.assertEqual(self.gate["main"](["--json"]), 2)
        report = json.loads(printed.call_args.args[0])
        self.assertFalse(report["fresh"])
        self.assertEqual(report["reasons"], ["existing LTO path: /etc/lto-archiver"])


if __name__ == "__main__":
    unittest.main()
