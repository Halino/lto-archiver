from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_REINTRODUCTION_PATHS = (
    "src/ltobackup/gui.py",
    "src/lto_backup_gui_entry.py",
    "src/lto_backup_entry.py",
    "src/pyi_rth_tkinter_local.py",
    "LtoBackupManager.spec",
    "hooks/hook-_tkinter.py",
    "hooks/pre_find_module_path/hook-tkinter.py",
    "requirements-build.txt",
    "packaging/version_info.txt",
    "packaging/version_info_cli.txt",
    "scripts/build-release.ps1",
    "scripts/verify-release.ps1",
    "scripts/install-lto-backup-manager.ps1",
    "scripts/configure-controlled-folder-access.ps1",
    "tests/test_gui.py",
    "tests/test_gui_english.py",
    "tests/test_cfa_installer.py",
    "tests/test_deployment_scripts.py",
    "scripts/field-tools/read-only/inspect_job_sqlite.py",
    "tests/test_entry.py",
    "docs/installation-windows.md",
    "scripts/field-tools/README.md",
    "scripts/field-tools/read-only/diagnose-live-io-detailed.ps1",
    "scripts/field-tools/read-only/diagnose-live-io.ps1",
    "scripts/field-tools/read-only/diagnose-live-job.ps1",
    "scripts/field-tools/read-only/diagnose-storeopen-mappings.ps1",
    "scripts/field-tools/read-only/inspect-antivirus-state.ps1",
    "scripts/field-tools/read-only/inspect-cfa-policy.ps1",
    "scripts/field-tools/read-only/inspect-defender-events.ps1",
    "scripts/field-tools/read-only/inspect-plan-state.ps1",
    "scripts/field-tools/read-only/inspect-run-lock.ps1",
    "scripts/field-tools/read-only/inspect-runtime-capabilities.ps1",
    "scripts/field-tools/read-only/inspect-storeopen-installation.ps1",
    "scripts/field-tools/read-only/inspect-storeopen-tools.ps1",
    "scripts/field-tools/read-only/inspect-tape-pnp-and-storeopen.ps1",
    "scripts/field-tools/read-only/probe-system-telemetry.ps1",
    "src/ltobackup/winio.py",
    "src/ltobackup/volume_probe.py",
    "src/ltobackup/cli.py",
    "src/ltobackup/__main__.py",
    "src/ltobackup/legacy_guard.py",
    "src/ltobackup/security.py",
    "tests/test_cli.py",
    "tests/test_security.py",
)
LINUX_LEAVES = (
    "src/ltobackup/daemon/main.py",
    "src/ltobackup/web/app.py",
    "src/ltobackup/web/templates/macros/forms.html",
    "src/ltobackup/qualification/cli.py",
    "src/ltobackup/migration/cli.py",
    "src/ltobackup/application.py",
    "src/ltobackup/automation.py",
    "src/ltobackup/filemeta.py",
    "src/ltobackup/volume.py",
    "config/config.toml.example",
    "docs/linux/migration.md",
    "docs/en/user-guide.md",
    "tests/test_linux_entrypoints.py",
)


def load_tool(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class LinuxReleaseExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.repository = cls.root / "repository"
        cls.repository.mkdir()
        checkout = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if checkout.returncode == 0 and Path(checkout.stdout.strip()) == ROOT:
            paths = (
                subprocess.check_output(
                    [
                        "git",
                        "ls-files",
                        "--cached",
                        "--others",
                        "--exclude-standard",
                        "-z",
                    ],
                    cwd=ROOT,
                )
                .decode()
                .split("\0")
            )
        else:
            # Source0 intentionally has no .git; test its committed policy too.
            paths = [
                path.relative_to(ROOT).as_posix()
                for path in ROOT.rglob("*")
                if path.is_file() and "__pycache__" not in path.parts
            ]
        paths.append("tests/test_linux_release_export.py")
        for relative in sorted(set(filter(None, paths))):
            source = ROOT / relative
            if source.is_file():
                destination = cls.repository / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        # Inject inert forbidden-path sentinels into the disposable repository.
        # They are reintroduction guards, not preserved implementations.
        for relative in FORBIDDEN_REINTRODUCTION_PATHS:
            destination = cls.repository / relative
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("historical release sentinel\n")
        for args in (
            ("init", "-q"),
            ("add", "."),
            (
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "disposable export",
            ),
        ):
            subprocess.run(
                ["git", *args],
                cwd=cls.repository,
                check=True,
                capture_output=True,
            )
        cls.commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=cls.repository, text=True
        ).strip()
        cls.release = cls.root / "release"
        (cls.release / "payload").mkdir(parents=True)
        cls.archive = cls.release / "payload/lto-archiver-0.11.27.tar.gz"
        subprocess.run(
            [
                "git",
                "archive",
                "--format=tar.gz",
                "--prefix=lto-archiver-0.11.27/",
                f"--output={cls.archive}",
                "HEAD",
                "--",
                ".",
                ":(exclude).superpowers/**",
                ":(exclude)docs/superpowers/**",
            ],
            cwd=cls.repository,
            check=True,
        )
        cls.export = cls.root / "export"
        cls.export.mkdir()
        with tarfile.open(cls.archive) as archive:
            archive.extractall(cls.export, filter="data")
        cls.export /= "lto-archiver-0.11.27"

    def test_committed_export_rejects_reintroduction_and_retains_linux_runtime(self):
        for relative in FORBIDDEN_REINTRODUCTION_PATHS:
            with self.subTest(excluded=relative):
                self.assertFalse((self.export / relative).exists())
        for relative in LINUX_LEAVES:
            with self.subTest(retained=relative):
                self.assertTrue((self.export / relative).is_file())

    def test_export_imports_linux_and_web_without_gui(self):
        environment = dict(os.environ, PYTHONPATH=str(self.export / "src"))
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                (
                    "import importlib.util; import ltobackup.daemon.main; "
                    "import ltobackup.web.app; import ltobackup.qualification.cli; "
                    "import ltobackup.migration.cli; "
                    "from pathlib import Path; "
                    "assert all(Path(m.__file__).is_relative_to(Path.cwd() / 'src') "
                    "for m in (ltobackup.daemon.main, ltobackup.web.app, "
                    "ltobackup.qualification.cli, ltobackup.migration.cli)); "
                    "assert importlib.util.find_spec('ltobackup.gui') is None"
                ),
            ],
            cwd=self.export,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_exported_build_entrypoints_remain_directly_executable(self):
        for relative in (
            "packaging/rpm/build-rhel9-rpm.sh",
            "packaging/rpm/release-rhel9-rpm.sh",
        ):
            with self.subTest(entrypoint=relative):
                entrypoint = self.export / relative
                self.assertTrue(os.access(entrypoint, os.X_OK))
                result = subprocess.run(
                    [str(entrypoint)],
                    cwd=self.export,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(2, result.returncode, result.stdout + result.stderr)
                self.assertIn("usage:", result.stderr)

    def test_export_runs_retained_linux_entrypoint_and_web_tests(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "unittest",
                "tests.test_linux_entrypoints",
                "tests.web.test_health",
            ],
            cwd=self.export,
            env=dict(os.environ, PYTHONPATH=str(self.export / "src")),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_export_agrees_with_canonical_auditor(self):
        (self.release / "release-contract.json").write_text(
            json.dumps(
                {
                    "kind": "application",
                    "package_name": "lto-archiver",
                    "version": "0.11.27-129",
                    "source_commit": self.commit,
                    "tag": "lto-archiver-v0.11.27-129",
                    "schema": 1,
                    "driver_nevra": "lto-ltfs-0.1.0-16.el9.x86_64",
                }
            )
        )
        auditor = load_tool("linux_export_auditor", "scripts/audit-release-content.py")
        _relative, findings = auditor._canonical_application_source(
            self.release, self.repository, self.commit
        )
        self.assertEqual((), findings)

    def test_main_rpm_rejects_reintroduced_removed_module_payload(self):
        verifier = load_tool(
            "linux_export_rpm_verifier", "packaging/rpm/verify-main-rpm.py"
        )
        contract = json.loads(
            (ROOT / "packaging/rpm/main-rpm-contract.json").read_text()
        )
        good = {
            path: tuple(metadata)
            for path, metadata in contract["required_payload_metadata"].items()
        }
        verifier._verify_payload_classes(
            SimpleNamespace(payload_metadata=good), contract
        )
        allowed_client = {
            **good,
            "/usr/lib/python3.11/site-packages/ltobackup/client.py": (
                "-rw-r--r--",
                "root",
                "root",
            ),
        }
        verifier._verify_payload_classes(
            SimpleNamespace(payload_metadata=allowed_client), contract
        )
        for path in (
            "/usr/lib/python3.11/site-packages/ltobackup/gui.py",
            "/usr/lib/python3.11/site-packages/ltobackup/__pycache__/gui.cpython-311.pyc",
            "/usr/lib/python3.11/site-packages/ltobackup/winio.py",
            "/usr/lib/python3.11/site-packages/ltobackup/__pycache__/winio.cpython-311.pyc",
            "/usr/lib/python3.11/site-packages/ltobackup/volume_probe.py",
            "/usr/lib/python3.11/site-packages/ltobackup/__pycache__/volume_probe.cpython-311.pyc",
            "/usr/lib/python3.11/site-packages/ltobackup/cli.py",
            "/usr/lib/python3.11/site-packages/ltobackup/__pycache__/cli.cpython-311.pyc",
            "/usr/lib/python3.11/site-packages/ltobackup/__main__.py",
            "/usr/lib/python3.11/site-packages/ltobackup/__pycache__/__main__.cpython-311.pyc",
            "/usr/lib/python3.11/site-packages/ltobackup/legacy_guard.py",
            "/usr/lib/python3.11/site-packages/ltobackup/__pycache__/legacy_guard.cpython-311.pyc",
            "/usr/lib/python3.11/site-packages/ltobackup/security.py",
            "/usr/lib/python3.11/site-packages/ltobackup/__pycache__/security.cpython-311.pyc",
            "/usr/bin/LtoBackupManager.exe",
            "/usr/bin/LtoBackupManagerCli.exe",
            "/usr/share/lto-archiver/install-lto-backup-manager.ps1",
        ):
            with self.subTest(path=path):
                payload = {**good, path: ["-rw-r--r--", "root", "root"]}
                with self.assertRaisesRegex(verifier.ContractError, "forbidden"):
                    verifier._verify_payload_classes(
                        SimpleNamespace(payload_metadata=payload), contract
                    )

    def test_auditor_does_not_exempt_removed_test_paths(self):
        auditor = load_tool(
            "linux_export_reintroduction_auditor",
            "scripts/audit-release-content.py",
        )
        fixtures = (
            (
                "tests/test_deployment_scripts.py",
                b'b"-----BEGIN ' + b'PRIVATE KEY-----\\nfixture"',
                "private-key",
            ),
            (
                "tests/test_gui.py",
                b'"source_root": r"\\\\nas\\share"',
                "private-unc-host",
            ),
        )
        for path, data, rule in fixtures:
            with self.subTest(path=path, rule=rule):
                self.assertIn(rule, {finding.rule for finding in auditor.audit_bytes(path, data)})
