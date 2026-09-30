from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOT = "/usr/lib64/lto-archiver/python-runtime/3.11/site-packages"
APPLICATION_ROOT = "/usr/lib/python3.11/site-packages"
LAUNCHERS = {
    "lto-archiver-admin": "ltobackup.admin_cli",
    "lto-archiver-command-broker": "ltobackup.broker.main",
    "lto-archiver-share-broker": "ltobackup.share_broker.main",
    "lto-archiverd": "ltobackup.daemon.main",
    "lto-archiver-migrate": "ltobackup.migration.cli",
    "lto-archiver-qualify-archive-runner": "ltobackup.qualification.archive_runner",
    "lto-archiver-qualify-ltfs": "ltobackup.qualification.cli",
    "lto-archiver-web": "ltobackup.web.main",
}
FIXED_ENTRYPOINTS = {
    **{
        name: (ROOT / "packaging" / "launchers" / name, module)
        for name, module in LAUNCHERS.items()
    },
    "preflight-rhel9.sh": (
        ROOT / "scripts" / "preflight-rhel9.sh",
        "ltobackup.preflight",
    ),
}


def write_module(root: Path, module: str, marker: str) -> None:
    package = root
    parts = module.split(".")
    for part in parts[:-1]:
        package /= part
        package.mkdir(exist_ok=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
    (package / f"{parts[-1]}.py").write_text(
        f"def main():\n    print({marker!r})\n    return 0\n",
        encoding="utf-8",
    )


class PythonRuntimeLauncherTests(unittest.TestCase):
    def test_device_policy_helper_uses_the_private_runtime_before_app_imports(
        self,
    ) -> None:
        helper = (
            ROOT / "packaging" / "scripts" / "configure-device-policy.py"
        ).read_text(encoding="utf-8")
        self.assertEqual("#!/usr/bin/python3.11 -I", helper.splitlines()[0])
        self.assertEqual(1, helper.count(PRIVATE_ROOT))
        self.assertEqual(1, helper.count(APPLICATION_ROOT))
        self.assertNotIn("PYTHONPATH", helper)
        self.assertIn("sys.dont_write_bytecode = True", helper)
        self.assertLess(
            helper.index(f'sys.path.insert(0, "{PRIVATE_ROOT}")'),
            helper.index("from ltobackup.errors import ValidationError"),
        )
        self.assertLess(
            helper.index(f'sys.path.insert(0, "{PRIVATE_ROOT}")'),
            helper.index(f'sys.path.insert(0, "{APPLICATION_ROOT}")'),
        )

    def test_ordinary_generated_launcher_is_influenced_by_pythonpath(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            attacker = root / "attacker"
            attacker.mkdir()
            write_module(attacker, "ltobackup.daemon.main", "attacker")
            launcher = root / "ordinary-launcher.py"
            launcher.write_text(
                "from ltobackup.daemon.main import main\nraise SystemExit(main())\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(attacker)
            result = subprocess.run(
                [sys.executable, str(launcher)],
                cwd=root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("attacker", result.stdout.strip())

    def test_fixed_launchers_ignore_hostile_environment_and_disable_bytecode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trusted = root / "trusted-application"
            stale_runtime = root / "stale-runtime"
            attacker = root / "attacker"
            cwd = root / "cwd"
            user_base = root / "user-base"
            user_site = (
                user_base
                / "lib"
                / f"python{sys.version_info.major}.{sys.version_info.minor}"
                / "site-packages"
            )
            for directory in (trusted, stale_runtime, attacker, cwd, user_site):
                directory.mkdir(parents=True)
            for module in {module for _, module in FIXED_ENTRYPOINTS.values()}:
                write_module(trusted, module, f"trusted:{module}")
                write_module(stale_runtime, module, f"stale-runtime:{module}")
                write_module(attacker, module, f"pythonpath:{module}")
                write_module(cwd, module, f"cwd:{module}")
                write_module(user_site, module, f"user:{module}")

            environment = os.environ.copy()
            environment.update(
                {
                    "PYTHONPATH": str(attacker),
                    "PYTHONHOME": str(root / "hostile-python-home"),
                    "PYTHONUSERBASE": str(user_base),
                }
            )
            for name, (source, module) in FIXED_ENTRYPOINTS.items():
                with self.subTest(launcher=name):
                    self.assertTrue(source.is_file(), source)
                    text = source.read_text(encoding="utf-8")
                    self.assertEqual("#!/usr/bin/python3.11 -I", text.splitlines()[0])
                    self.assertEqual(1, text.count(PRIVATE_ROOT))
                    self.assertEqual(1, text.count(APPLICATION_ROOT))
                    self.assertNotIn("PYTHONPATH", text)
                    self.assertNotIn("PYTHONHOME", text)
                    self.assertNotIn("importlib", text)
                    runnable = root / f"{name}.py"
                    runnable.write_text(
                        text.replace(APPLICATION_ROOT, str(trusted)).replace(
                            PRIVATE_ROOT, str(stale_runtime)
                        ),
                        encoding="utf-8",
                    )
                    result = subprocess.run(
                        [sys.executable, "-I", str(runnable)],
                        cwd=cwd,
                        env=environment,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual(f"trusted:{module}", result.stdout.strip())
            self.assertEqual([], list(trusted.rglob("*.pyc")))

    def test_spec_overwrites_all_generated_launchers_as_root_owned_files(self) -> None:
        spec = (ROOT / "packaging/rpm/lto-archiver.spec").read_text(encoding="utf-8")
        install_section = spec.split("%install\n", 1)[1].split("\n%check\n", 1)[0]
        files_section = spec.split("%files -f %{pyproject_files}\n", 1)[1].split(
            "\n%changelog\n", 1
        )[0]
        for name in LAUNCHERS:
            with self.subTest(launcher=name):
                self.assertIn(f"packaging/launchers/{name}", install_section)
                self.assertIn(
                    f"%attr(0755,root,root) %{{_bindir}}/{name}", files_section
                )

    def test_all_launchers_retain_explicit_selinux_contexts(self) -> None:
        contexts = (ROOT / "packaging/selinux/lto_archiver.fc").read_text(
            encoding="utf-8"
        )
        for name in LAUNCHERS:
            with self.subTest(launcher=name):
                self.assertIn(f"/usr/bin/{name}", contexts)


if __name__ == "__main__":
    unittest.main()
