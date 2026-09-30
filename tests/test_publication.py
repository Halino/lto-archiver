"""Behavioral checks for a deliberately history-free public source export."""

from __future__ import annotations

import io
import importlib.util
import re
import runpy
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTER = ROOT / "scripts" / "build-public-snapshot.py"


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


class PublicSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="lto-public-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        _git(self.source, "init", "-q")
        _git(self.source, "config", "user.name", "Fixture Author")
        _git(self.source, "config", "user.email", "fixture@example.invalid")
        (self.source / "src").mkdir()
        (self.source / "src" / "example.py").write_text("VALUE = 1\n", encoding="utf-8")
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "fixture source")
        self.manifest = self.root / "public-files.txt"
        self.manifest.write_text("src/example.py\n", encoding="utf-8")
        self.output = self.root / "public"

    def export(self, commit: str | None = None) -> Path:
        self.assertTrue(EXPORTER.is_file(), "public snapshot exporter is missing")
        build_public_snapshot = runpy.run_path(str(EXPORTER))["build_public_snapshot"]
        return build_public_snapshot(
            self.source,
            commit or _git(self.source, "rev-parse", "HEAD"),
            self.manifest,
            self.output,
        )

    def test_current_export_allowlist_keeps_release_verification_chain(self) -> None:
        paths = set(runpy.run_path(str(EXPORTER))["_manifest_paths"](ROOT / "public-files.txt"))
        required = {
            ".github/workflows/build-release.yml",
            ".github/workflows/ci.yml",
            ".github/workflows/publish-release.yml",
            "docs/en/github-rpm-verification.md",
            "docs/linux/public-fresh-install-smoke.md",
            "packaging/rpm/build-public-unsigned.py",
            "packaging/rpm/check-public-fresh-host.py",
            "packaging/rpm/verify-public-artifacts.py",
            "packaging/rpm/verify-public-fresh-smoke.py",
            "packaging/rpm/verify-public-release.py",
            "tests/test_public_fresh_host.py",
            "tests/test_public_fresh_smoke.py",
            "tests/test_public_main_rpm_contract.py",
            "tests/test_public_release_auxiliary.py",
            "tests/test_public_release_gate.py",
            "tests/test_public_release_immutability_proof.py",
            "tests/test_public_release_pipeline.py",
            "tests/test_public_release_publication.py",
            "tests/test_public_unsigned_build.py",
            "tests/test_public_workflow_policy.py",
        }
        self.assertEqual(required - paths, set())

    def test_rpm_check_modules_are_shipped_and_importable(self) -> None:
        spec = (ROOT / "packaging/rpm/lto-archiver.spec").read_text(encoding="utf-8")
        modules = re.findall(
            r"(?m)^PYTHONPATH=.*? -m unittest (tests\.[A-Za-z_]+) -v$", spec
        )
        self.assertTrue(modules, "RPM spec has no checked test modules")
        manifest = set(
            runpy.run_path(str(EXPORTER))["_manifest_paths"](ROOT / "public-files.txt")
        )
        for module in modules:
            path = module.replace(".", "/") + ".py"
            with self.subTest(module=module):
                self.assertTrue(path in manifest, f"RPM check module omitted: {path}")
                self.assertIsNotNone(importlib.util.find_spec(module))

    def test_export_has_one_new_commit_without_private_parent_history(self) -> None:
        historical = self.source / "old-private.txt"
        historical.write_text("PRIVATE_OPERATION_TOKEN\n", encoding="utf-8")
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "historical private state")
        historical.unlink()
        _git(self.source, "add", "-u")
        _git(self.source, "commit", "-qm", "remove private state")

        exported = self.export()

        self.assertEqual(exported, self.output)
        self.assertEqual(_git(exported, "rev-list", "--count", "--all"), "1")
        self.assertEqual((exported / "src" / "example.py").read_text(), "VALUE = 1\n")
        self.assertNotIn("PRIVATE_OPERATION_TOKEN", _git(exported, "log", "-p", "--all"))
        self.assertFalse((exported / "old-private.txt").exists())

    def test_rejects_committed_symlink_escaping_source(self) -> None:
        (self.source / "src" / "outside.py").symlink_to("../../../outside.py")
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "unsafe link")
        self.manifest.write_text("src/outside.py\n", encoding="utf-8")

        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_rejects_nested_archive_with_private_address(self) -> None:
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("config.txt", ".".join(("10", "123", "45", "67")))
        (self.source / "src" / "nested.zip").write_bytes(payload.getvalue())
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "nested archive")
        self.manifest.write_text("src/nested.zip\n", encoding="utf-8")

        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_rejects_untracked_manifest_member(self) -> None:
        (self.source / "src" / "dirty.py").write_text("VALUE = 2\n", encoding="utf-8")
        self.manifest.write_text("src/dirty.py\n", encoding="utf-8")

        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())


    def test_source_cannot_replace_the_trusted_content_auditor(self) -> None:
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("config.txt", ".".join(("10", "123", "45", "67")))
        (self.source / "src" / "nested.zip").write_bytes(payload.getvalue())
        fake_auditor = self.source / "scripts" / "audit-release-content.py"
        fake_auditor.parent.mkdir()
        fake_auditor.write_text(
            "def audit_directory(root): return ()\n"
            "def audit_git_history(root): return ()\n",
            encoding="utf-8",
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "fake auditor")
        self.manifest.write_text("src/nested.zip\n", encoding="utf-8")

        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())


    def test_rejects_a_history_audit_exception(self) -> None:
        namespace = runpy.run_path(str(EXPORTER))
        auditor = namespace["_auditor"]()
        auditor.audit_git_history = lambda root: (
            auditor.AuditFinding(
                path="<git-history>",
                rule="git-read-error",
                detail="synthetic history failure",
            ),
        )
        build = namespace["build_public_snapshot"]
        build.__globals__["_auditor"] = lambda: auditor
        with self.assertRaises(ValueError):
            build(
                self.source,
                _git(self.source, "rev-parse", "HEAD"),
                self.manifest,
                self.output,
            )
        self.assertFalse(self.output.exists())


    def test_allows_variable_credential_handling_without_a_literal_secret(self) -> None:
        (self.source / "src" / "example.py").write_text(
            "token = acquire_token()\n", encoding="utf-8"
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "runtime token handling")

        try:
            exported = self.export()
        except ValueError as exc:
            self.fail(f"safe source was rejected: {exc}")
        self.assertEqual(exported, self.output)

    def test_allows_standard_rfc1918_policy_cidr_not_a_host(self) -> None:
        (self.source / "src" / "example.py").write_text(
            'ALLOWED_CIDRS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")\n',
            encoding="utf-8",
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "standard LAN policy")

        try:
            exported = self.export()
        except ValueError as exc:
            self.fail(f"safe source was rejected: {exc}")
        self.assertEqual(exported, self.output)

    def test_rejects_literal_password_in_public_code(self) -> None:
        (self.source / "src" / "example.py").write_text(
            'password = "actual-private-value"\n', encoding="utf-8"
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "bad fixture")

        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())


    def test_allows_standard_cidr_in_public_config_example(self) -> None:
        (self.source / "config").mkdir()
        (self.source / "config" / "policy.toml").write_text(
            'allowed_ipv4_cidrs = ["10.0.0.0/8"]\n', encoding="utf-8"
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "standard policy example")
        self.manifest.write_text("config/policy.toml\n", encoding="utf-8")

        try:
            exported = self.export()
        except ValueError as exc:
            self.fail(f"safe policy example was rejected: {exc}")
        self.assertEqual(exported, self.output)

    def test_rejects_private_host_in_public_code(self) -> None:
        host = ".".join(("10", "123", "45", "67"))
        (self.source / "src" / "example.py").write_text(
            f'PRIVATE_HOST = "{host}"\n', encoding="utf-8"
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "private host fixture")

        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())


    def test_rejects_private_media_label_in_product_source(self) -> None:
        (self.source / "src" / "example.py").write_text(
            'EXPECTED_MEDIA = "' + "IR" + "9876" + '"\\n', encoding="utf-8"
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "private media fixture")
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_rejects_lowercase_private_media_label(self) -> None:
        (self.source / "src" / "example.py").write_text(
            'label = "' + "ir" + "9876" + '"\\n', encoding="utf-8"
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "lowercase media fixture")
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())


    def test_lowercase_identity_is_explicitly_classified(self) -> None:
        (self.source / "src" / "example.py").write_text(
            '# "' + "ir" + "9876" + '"\\n', encoding="utf-8"
        )
        exporter = runpy.run_path(str(EXPORTER))
        findings = exporter["_source_audit_findings"](
            self.source, exporter["_auditor"]()
        )
        self.assertIn("private-operation-identity", {item.rule for item in findings})


    def test_rejects_private_job_identifier_in_product_source(self) -> None:
        (self.source / "src" / "example.py").write_text(
            'JOB = "' + "AUTO-" + "20260101-010203-123456" + '"\\n', encoding="utf-8"
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "private job fixture")
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())


    def test_allows_comparison_of_runtime_token(self) -> None:
        (self.source / "src" / "example.py").write_text(
            "if token == expected:\n    pass\n", encoding="utf-8"
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "token comparison")
        try:
            exported = self.export()
        except ValueError as exc:
            self.fail(f"safe comparison was rejected: {exc}")
        self.assertEqual(exported, self.output)

    def test_rejects_literal_secret_in_dictionary(self) -> None:
        (self.source / "src" / "example.py").write_text(
            'CREDENTIALS = {"password": "actual-private-value"}\n',
            encoding="utf-8",
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "literal secret dictionary")
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())


    def test_reviewed_product_literals_do_not_block_public_source(self) -> None:
        namespace = runpy.run_path(str(EXPORTER))
        auditor = namespace["_auditor"]()
        findings = namespace["_source_audit_findings"](ROOT, auditor)
        problematic = {
            finding.path for finding in findings
            if finding.rule == "literal-credential"
        }
        self.assertFalse(
            problematic.intersection({
                "src/ltobackup/operational_log.py",
                "src/ltobackup/web/app.py",
                "src/ltobackup/daemon/service.py",
                "src/ltobackup/broker/main.py",
            })
        )

    def test_reviewed_web_fixtures_are_bound_to_exact_file_bytes(self) -> None:
        namespace = runpy.run_path(str(EXPORTER))
        auditor = namespace["_auditor"]()
        check = namespace["_safe_python_literals"]
        for relative in (
            "tests/web/test_management_views.py",
            "tests/web/test_layout_chromium.py",
        ):
            with self.subTest(relative=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertTrue(check(text, auditor, relative))
                self.assertFalse(
                    check(text + "\n# changed fixture\n", auditor, relative)
                )

    def test_changed_product_credential_scope_literal_is_rejected(self) -> None:
        path = self.source / "src" / "ltobackup" / "daemon" / "service.py"
        path.parent.mkdir(parents=True)
        path.write_text(
            'PEER_CREDENTIAL_SCOPE_KEY = "not-reviewed-value"\n',
            encoding="utf-8",
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "changed scope fixture")
        self.manifest.write_text(
            "src/ltobackup/daemon/service.py\n", encoding="utf-8"
        )
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())


    def test_allows_js_token_comparison(self) -> None:
        (self.source / "src" / "example.js").write_text(
            "if (token === expected) {}\n", encoding="utf-8"
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "js comparison")
        self.manifest.write_text("src/example.js\n", encoding="utf-8")
        try:
            exported = self.export()
        except ValueError as exc:
            self.fail(f"safe JS comparison was rejected: {exc}")
        self.assertEqual(exported, self.output)

    def test_allows_js_password_input_reference(self) -> None:
        (self.source / "src" / "example.js").write_text(
            'const password = dialog.querySelector("#protected-password");\n',
            encoding="utf-8",
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "js field reference")
        self.manifest.write_text("src/example.js\n", encoding="utf-8")
        try:
            exported = self.export()
        except ValueError as exc:
            self.fail(f"safe DOM reference was rejected: {exc}")
        self.assertEqual(exported, self.output)

    def test_rejects_js_literal_password(self) -> None:
        (self.source / "src" / "example.js").write_text(
            'const password = "actual-private-value";\n', encoding="utf-8"
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "js literal fixture")
        self.manifest.write_text("src/example.js\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_allows_systemd_credential_file_reference(self) -> None:
        (self.source / "packaging").mkdir()
        unit = self.source / "packaging" / "broker.service"
        unit.write_text(
            "[Service]\nUser=root\n"
            "LoadCredential=qualification-credential:/etc/lto-archiver/credentials/qualification-credential\n",
            encoding="utf-8",
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "systemd credential reference")
        self.manifest.write_text("packaging/broker.service\n", encoding="utf-8")
        try:
            exported = self.export()
        except ValueError as exc:
            self.fail(f"safe systemd reference was rejected: {exc}")
        self.assertEqual(exported, self.output)


    def test_allows_exact_packaged_deployment_tool_path(self) -> None:
        (self.source / "packaging").mkdir()
        (self.source / "packaging" / "build.sh").write_text(
            "install packaging/scripts/deploy-rhel9.py /tmp/product-tool\n",
            encoding="utf-8",
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "product deploy input")
        self.manifest.write_text("packaging/build.sh\n", encoding="utf-8")
        try:
            exported = self.export()
        except ValueError as exc:
            self.fail(f"packaged source path was rejected: {exc}")
        self.assertEqual(exported, self.output)

    def test_rejects_private_ci_reference(self) -> None:
        (self.source / "private.md").write_text(
            "Do not export .gitlab-ci.yml\n", encoding="utf-8"
        )
        _git(self.source, "add", ".")
        _git(self.source, "commit", "-qm", "private ci fixture")
        self.manifest.write_text("private.md\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
