from __future__ import annotations

import hashlib
import importlib
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _parse_workflow_yaml(text: str) -> dict[str, object]:
    """Parse the mapping/list/block-scalar YAML subset used by these workflows."""

    lines = text.splitlines()

    def scalar(value: str) -> str:
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            return value[1:-1]
        return value

    def next_content(index: int) -> int:
        while index < len(lines) and not lines[index].strip():
            index += 1
        return index

    def parse_block(index: int, indent: int) -> tuple[object, int]:
        index = next_content(index)
        if index >= len(lines):
            return None, index
        if len(lines[index]) - len(lines[index].lstrip()) != indent:
            raise ValueError("unexpected YAML indentation")
        is_list = lines[index].lstrip().startswith("- ")
        result: object = [] if is_list else {}
        while index < len(lines):
            index = next_content(index)
            if index >= len(lines):
                break
            line = lines[index]
            current_indent = len(line) - len(line.lstrip())
            if current_indent < indent:
                break
            if current_indent != indent:
                raise ValueError("unexpected YAML indentation")
            body = line.lstrip()
            if is_list:
                if not body.startswith("- "):
                    raise ValueError("mixed YAML collection")
                body = body[2:]
                if ":" not in body:
                    result.append(scalar(body))  # type: ignore[union-attr]
                    index += 1
                    continue
                key, value = body.split(":", 1)
                item: dict[str, object] = {key: scalar(value)}
                index += 1
                child_index = next_content(index)
                if child_index < len(lines):
                    child_indent = len(lines[child_index]) - len(lines[child_index].lstrip())
                    if child_indent > indent:
                        child, index = parse_block(child_index, child_indent)
                        if not isinstance(child, dict):
                            raise ValueError("list item continuation must be a mapping")
                        item.update(child)
                result.append(item)  # type: ignore[union-attr]
                continue
            if body.startswith("- ") or ":" not in body:
                raise ValueError("invalid YAML mapping entry")
            key, value = body.split(":", 1)
            value = value.strip()
            index += 1
            if value == "|":
                block_lines: list[str] = []
                while index < len(lines):
                    block_line = lines[index]
                    if block_line.strip():
                        block_indent = len(block_line) - len(block_line.lstrip())
                        if block_indent <= indent:
                            break
                        block_lines.append(block_line[indent + 2 :])
                    else:
                        block_lines.append("")
                    index += 1
                result[key] = "\n".join(block_lines).rstrip()  # type: ignore[index]
                continue
            if value:
                result[key] = scalar(value)  # type: ignore[index]
                continue
            child_index = next_content(index)
            if child_index >= len(lines):
                result[key] = None  # type: ignore[index]
                continue
            child_indent = len(lines[child_index]) - len(lines[child_index].lstrip())
            if child_indent <= indent:
                result[key] = None  # type: ignore[index]
                continue
            child, index = parse_block(child_index, child_indent)
            result[key] = child  # type: ignore[index]
        return result, index

    parsed, index = parse_block(0, 0)
    if next_content(index) != len(lines) or not isinstance(parsed, dict):
        raise ValueError("workflow must be one complete YAML mapping")
    return parsed


class PublicationTests(unittest.TestCase):
    def test_public_checkout_preserves_canonical_lf_bytes(self) -> None:
        attributes = ROOT / ".gitattributes"

        self.assertTrue(attributes.is_file())
        self.assertIn("* text=auto eol=lf", attributes.read_text(encoding="utf-8"))
        self.assertIn(".gitattributes", (ROOT / "public-files.txt").read_text(encoding="utf-8"))

    def test_apache_license_and_owner_are_declared(self) -> None:
        license_bytes = (ROOT / "LICENSE").read_bytes()
        license_text = license_bytes.decode("utf-8")
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertEqual(
            "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
            hashlib.sha256(license_bytes).hexdigest(),
        )
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0, January 2004", license_text)
        self.assertIn("END OF TERMS AND CONDITIONS", license_text)
        self.assertIn("Copyright 2026 Alessandro Gnagni", notice)
        self.assertIn('license = "Apache-2.0"', metadata)

    def test_third_party_notices_cover_declared_build_dependencies(self) -> None:
        notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        requirements = (ROOT / "requirements-build.txt").read_text(encoding="utf-8")
        self.assertIn("pyinstaller==6.22.0", requirements.casefold())
        self.assertIn("PyInstaller 6.22.0", notices)
        self.assertIn("PyInstaller Bootloader Exception", notices)
        self.assertIn("HPE software is not distributed", notices)

    def test_github_community_files_cover_safety_and_redaction(self) -> None:
        names = ("CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md", "CODE_OF_CONDUCT.md")
        for name in names:
            self.assertTrue((ROOT / name).is_file(), name)
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        support = (ROOT / "SUPPORT.md").read_text(encoding="utf-8")
        pull_request = (ROOT / ".github" / "pull_request_template.md").read_text(encoding="utf-8")
        self.assertIn("Do not open a public issue", security)
        self.assertIn(
            "After the GitHub repository has been created and private vulnerability reporting "
            "has been configured",
            security,
        )
        self.assertNotIn("Until that channel is available", security)
        self.assertIn("support ticket", support.casefold())
        self.assertIn("Destructive tape operation", pull_request)

    def test_public_manifest_is_exact_and_excludes_private_operations(self) -> None:
        manifest = (ROOT / "public-files.txt").read_text(encoding="utf-8").splitlines()
        files = [line for line in manifest if line and not line.startswith("#")]
        self.assertEqual(files, sorted(set(files)))
        self.assertIn(".github/workflows/ci.yml", files)
        self.assertIn(".github/workflows/release.yml", files)
        self.assertIn("src/ltobackup/gui.py", files)
        self.assertIn("docs/en/user-guide.md", files)
        self.assertIn("docs/it/user-guide.md", files)
        self.assertIn("scripts/__init__.py", files)
        forbidden = (
            ".gitlab" + "-ci.yml",
            "docs/review-",
            "docs/superpowers/",
            "release/",
            "scripts/deploy" + "-",
            "scripts/field-tools/archive/",
            "scripts/field-tools/controlled/",
            "scripts/inspect-ltfs-reserve.ps1",
            "scripts/inspect-storeopen-cli.ps1",
            "scripts/preflight-storeopen.ps1",
            "scripts/smoke-installed-gui.ps1",
            "scripts/verify-installed-manager.ps1",
        )
        self.assertFalse(any(path.startswith(forbidden) or path in forbidden for path in files))

    def test_public_tests_do_not_depend_on_private_deployment_files(self) -> None:
        deployment_tests = (ROOT / "tests" / "test_deployment_scripts.py").read_text(
            encoding="utf-8"
        )
        for private_path in (
            ".gitlab" + "-ci.yml",
            "deploy" + "-01126-safe.ps1",
            "verify" + "-installed-manager.ps1",
        ):
            self.assertNotIn(private_path, deployment_tests)

    def test_github_workflows_test_and_verify_before_release(self) -> None:
        ci = _parse_workflow_yaml((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
        release = _parse_workflow_yaml(
            (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        )

        self.assertEqual({"push": {"branches": ["main"]}, "pull_request": None}, ci["on"])
        self.assertEqual({"contents": "read"}, ci["permissions"])
        ci_job = ci["jobs"]["test"]
        self.assertEqual("windows-latest", ci_job["runs-on"])
        self.assertEqual(
            ["actions/checkout@v4", "actions/setup-python@v5"],
            [step["uses"] for step in ci_job["steps"] if "uses" in step],
        )
        self.assertEqual({"python-version": "3.11"}, ci_job["steps"][1]["with"])
        self.assertIn("unittest discover -s tests -v", ci_job["steps"][-2]["run"])
        self.assertIn("audit-public-content.py", ci_job["steps"][-1]["run"])

        self.assertEqual({"push": {"tags": ["v*.*.*"]}}, release["on"])
        self.assertEqual({"contents": "write"}, release["permissions"])
        release_job = release["jobs"]["release"]
        self.assertEqual("windows-latest", release_job["runs-on"])
        checkout = release_job["steps"][0]
        self.assertEqual("actions/checkout@v4", checkout["uses"])
        self.assertEqual({"fetch-depth": "0", "persist-credentials": "false"}, checkout["with"])
        self.assertEqual("actions/setup-python@v5", release_job["steps"][1]["uses"])
        self.assertEqual({"python-version": "3.11"}, release_job["steps"][1]["with"])
        self.assertEqual(
            ["actions/checkout@v4", "actions/setup-python@v5"],
            [step["uses"] for step in release_job["steps"] if "uses" in step],
        )
        self.assertEqual(
            [
                "Run complete unittest suite",
                "Audit the exact public source manifest",
                "Build release archive",
                "Verify release archive",
                "Audit release archive",
                "Publish verified release",
            ],
            [step["name"] for step in release_job["steps"][-6:]],
        )
        publication = release_job["steps"][-1]
        self.assertEqual({"GH_TOKEN": "${{ github.token }}"}, publication["env"])
        self.assertFalse(any("GH_TOKEN" in step.get("env", {}) for step in release_job["steps"][:-1]))
        self.assertEqual(
            "\n".join(
                (
                    "$version = $env:RELEASE_VERSION",
                    "gh release create $env:GITHUB_REF_NAME `",
                    '  "release/LTO-Archiver-$version.zip" `',
                    '  "release/LTO-Archiver-$version.zip.sha256" `',
                    '  --title "LTO Archiver $version" `',
                    '  --notes-file "docs/release-notes-$version.md" `',
                    "  --verify-tag",
                )
            ),
            publication["run"],
        )
        for workflow in (ci, release):
            rendered = str(workflow)
            self.assertNotIn("pull_request_target", rendered)
            self.assertNotIn("self-hosted", rendered)
            self.assertNotIn("Invoke-WebRequest", rendered)
            self.assertNotIn("curl ", rendered)
            self.assertNotIn("wget ", rendered)

    def test_snapshot_modules_expose_stable_import_seams(self) -> None:
        builder = importlib.import_module("scripts.build_public_snapshot")
        auditor = importlib.import_module("scripts.audit_public_content")
        self.assertTrue(callable(builder.load_manifest))
        self.assertTrue(callable(builder.build_snapshot))
        self.assertTrue(hasattr(auditor.AuditFinding, "__dataclass_fields__"))

    def test_manifest_reader_returns_normalized_relative_files(self) -> None:
        builder = importlib.import_module("scripts.build_public_snapshot")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "README.md").write_bytes(b"readme\r\n")
            (root / "docs" / "guide.md").write_bytes(b"guide\n")
            manifest = root / "manifest.txt"
            manifest.write_text("README.md\ndocs/guide.md\n", encoding="utf-8")

            self.assertEqual(
                (Path("README.md"), Path("docs/guide.md")),
                builder.load_manifest(root, manifest),
            )

    def test_manifest_reader_rejects_unsafe_or_ambiguous_entries(self) -> None:
        builder = importlib.import_module("scripts.build_public_snapshot")
        invalid_manifests = {
            "absolute-posix": "/etc/passwd\n",
            "absolute-windows": "C:/Users/example/secret.txt\n",
            "unc": "//server/share/file.txt\n",
            "traversal": "../secret.txt\n",
            "backslash": "docs\\guide.md\n",
            "dot-component": "docs/./guide.md\n",
            "git-metadata": ".git/config\n",
            "glob": "docs/*.md\n",
            "duplicate": "README.md\nREADME.md\n",
            "unsorted": "docs/guide.md\nREADME.md\n",
            "whitespace": " README.md\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "README.md").write_text("readme", encoding="utf-8")
            (root / "docs" / "guide.md").write_text("guide", encoding="utf-8")
            manifest = root / "manifest.txt"
            for label, content in invalid_manifests.items():
                with self.subTest(label=label):
                    manifest.write_text(content, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        builder.load_manifest(root, manifest)

    def test_manifest_reader_rejects_missing_files_directories_and_symlinks(self) -> None:
        builder = importlib.import_module("scripts.build_public_snapshot")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "directory").mkdir()
            (root / "real.txt").write_text("real", encoding="utf-8")
            symlink = root / "link.txt"
            try:
                symlink.symlink_to(root / "real.txt")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            manifest = root / "manifest.txt"
            for entry in ("missing.txt", "directory", "link.txt"):
                with self.subTest(entry=entry):
                    manifest.write_text(f"{entry}\n", encoding="utf-8")
                    with self.assertRaises(ValueError):
                        builder.load_manifest(root, manifest)

    def test_snapshot_copies_only_manifest_bytes_without_git_metadata(self) -> None:
        builder = importlib.import_module("scripts.build_public_snapshot")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "source"
            target = base / "snapshot"
            (root / "docs").mkdir(parents=True)
            (root / ".git").mkdir()
            (root / "README.md").write_bytes(b"readme\r\n")
            (root / "docs" / "guide.md").write_bytes(b"guide\x00bytes")
            (root / "private.txt").write_text("private", encoding="utf-8")

            builder.build_snapshot(
                root,
                target,
                (Path("README.md"), Path("docs/guide.md")),
            )

            copied = sorted(
                path.relative_to(target).as_posix()
                for path in target.rglob("*")
                if path.is_file()
            )
            self.assertEqual(["README.md", "docs/guide.md"], copied)
            self.assertEqual(b"readme\r\n", (target / "README.md").read_bytes())
            self.assertEqual(b"guide\x00bytes", (target / "docs" / "guide.md").read_bytes())

    def test_snapshot_rejects_target_inside_source_or_nonempty_target(self) -> None:
        builder = importlib.import_module("scripts.build_public_snapshot")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            (root / "README.md").write_text("readme", encoding="utf-8")
            with self.assertRaises(ValueError):
                builder.build_snapshot(root, root / "snapshot", (Path("README.md"),))
            target = Path(temporary) / "target"
            target.mkdir()
            (target / "existing.txt").write_text("keep", encoding="utf-8")
            with self.assertRaises(ValueError):
                builder.build_snapshot(root, target, (Path("README.md"),))
            self.assertEqual("keep", (target / "existing.txt").read_text(encoding="utf-8"))

    def test_content_audit_rejects_private_networks_keys_credentials_and_tokens(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        samples = {
            "private-network": b"host=" + b"10.1" + b".2.3",
            "private-key": b"-----BEGIN OPEN" + b"SSH PRIVATE KEY-----",
            "credential": b"pass" + b"word=CorrectHorseBatteryStaple",
            "github-token": b"token=" + b"ghp_abcdefghijklmnop" + b"qrstuvwxyz0123456789",
            "unc-host": b"share=" + (b"\\" * 2) + b"files.co" + b"rp.lo" + b"cal\\archive",
            "user-profile": b"path=C:" + b"\\" + b"Users\\alice\\catalog",
        }
        for rule, sample in samples.items():
            with self.subTest(rule=rule):
                findings = auditor.audit_bytes("sample.txt", sample)
                self.assertTrue(findings)
                rendered = "\n".join(f"{finding.rule} {finding.detail}" for finding in findings)
                for secret in (
                    "CorrectHorseBatteryStaple",
                    "ghp_abcdefghijklmnop" + "qrstuvwxyz0123456789",
                ):
                    self.assertNotIn(secret, rendered)

    def test_content_audit_allows_reserved_documentation_examples(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        examples = (
            b"host=" + b"192.0.2.10 peer=198.51.100.7 gateway=203.0.113.5",
            b"share=" + (b"\\" * 2) + b"files.example.test\\archive user=<username> password=<redacted>",
            b"media=MEDIA_01 barcode=ABC123L6",
        )
        for sample in examples:
            with self.subTest(sample=sample):
                self.assertFalse(auditor.audit_bytes("manual.md", sample))

    def test_content_audit_rejects_every_non_global_special_ipv4_range(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        addresses = (
            "0.1" + ".2.3",
            "127.0" + ".0.1",
            "169.254" + ".20.30",
            "192.0" + ".0.8",
            "198.18" + ".0.1",
            "224.0" + ".0.1",
            "240.0" + ".0.1",
        )
        for address in addresses:
            with self.subTest(address=address):
                findings = auditor.audit_bytes("sample.txt", f"host={address}".encode("ascii"))
                self.assertTrue(any(finding.rule == "private-network" for finding in findings))

    def test_content_audit_rejects_globally_routable_iana_special_ipv4_ranges(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        addresses = (
            "192.31" + ".196.1",
            "192.52" + ".193.1",
            "192.88" + ".99.1",
            "192.175" + ".48.1",
        )
        for address in addresses:
            with self.subTest(address=address):
                findings = auditor.audit_bytes("sample.txt", f"host={address}".encode("ascii"))
                self.assertTrue(any(finding.rule == "private-network" for finding in findings))

    def test_content_audit_covers_the_complete_iana_special_ipv4_registry(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        registry_examples = (
            ("this-network", "0.1" + ".2.3"),
            ("this-host", "0.0" + ".0.0"),
            ("private-10", "10.1" + ".2.3"),
            ("shared-address", "100.64" + ".0.1"),
            ("loopback", "127.0" + ".0.1"),
            ("link-local", "169.254" + ".1.1"),
            ("private-172", "172.16" + ".0.1"),
            ("ietf-protocol-assignments", "192.0" + ".0.1"),
            ("ipv4-service-continuity", "192.0" + ".0.7"),
            ("dummy-address", "192.0" + ".0.8"),
            ("pcp-anycast", "192.0" + ".0.9"),
            ("turn-anycast", "192.0" + ".0.10"),
            ("nat64-discovery-a", "192.0" + ".0.170"),
            ("nat64-discovery-b", "192.0" + ".0.171"),
            ("as112-v4", "192.31" + ".196.1"),
            ("amt", "192.52" + ".193.1"),
            ("deprecated-6to4", "192.88" + ".99.1"),
            ("6a44-relay-anycast", "192.88" + ".99.2"),
            ("private-192", "192.168" + ".0.1"),
            ("direct-delegation-as112", "192.175" + ".48.1"),
            ("benchmarking", "198.18" + ".0.1"),
            ("multicast", "224.0" + ".0.1"),
            ("reserved", "240.0" + ".0.1"),
            ("limited-broadcast", "255.255" + ".255.255"),
        )
        for name, address in registry_examples:
            with self.subTest(name=name, address=address):
                findings = auditor.audit_bytes("sample.txt", f"host={address}".encode("ascii"))
                self.assertTrue(any(finding.rule == "private-network" for finding in findings))

    def test_four_part_file_version_is_not_mistaken_for_an_ipv4_address(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        version = b"0.11" + b".27.0"
        self.assertFalse(auditor.audit_bytes("release.txt", b"file/product version " + version))
        self.assertTrue(auditor.audit_bytes("sample.txt", b"host=" + version))
        historical = b"0.11" + b".26.0"
        self.assertFalse(
            auditor.audit_bytes("historical-release.txt", b"file version " + historical)
        )
        self.assertTrue(auditor.audit_bytes("sample.txt", b"host=" + historical))
        private_version = b"10.0" + b".0.1"
        self.assertTrue(auditor.audit_bytes("release.txt", b"file version " + private_version))

    def test_sensitive_values_in_paths_are_scanned_and_redacted_across_sources(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        private_address = "198.18" + ".0.44"
        live_token = "ghp_abcdefghijklmnop" + "qrstuvwxyz0123456789"
        internal_host = "backup.co" + "rp.lo" + "cal"
        unc_host = "files.co" + "rp.lo" + "cal"
        findings = list(
            auditor.audit_bytes(
                ("share=" + ("\\" * 2) + unc_host + "\\archive\\safe.txt"),
                b"safe",
            )
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / f"host={private_address}.txt").write_text("safe", encoding="utf-8")
            findings.extend(auditor.audit_directory(root))

            archive = root / "paths.zip"
            token_prefix = "to" + "ken="
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(f"{token_prefix}{live_token}.txt", b"safe")
            findings.extend(auditor.audit_zip(archive))

            repository = root / "repository"
            repository.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.name", "Audit Test"], cwd=repository, check=True)
            subprocess.run(
                ["git", "config", "user.email", "audit@example.test"], cwd=repository, check=True
            )
            account_prefix = "us" + "er=alice@"
            (repository / f"{account_prefix}{internal_host}.txt").write_text("safe", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "path fixture"], cwd=repository, check=True)
            findings.extend(auditor.audit_git_history(repository))

        rules = {finding.rule for finding in findings}
        self.assertIn("private-network", rules)
        self.assertIn("private-unc-host", rules)
        self.assertIn("secret-token", rules)
        self.assertIn("credential-assignment", rules)
        self.assertIn("internal-host", rules)
        rendered = "\n".join(f"{finding.path} {finding.detail}" for finding in findings)
        for secret in (private_address, live_token, internal_host, unc_host, "alice"):
            self.assertNotIn(secret, rendered)

    def test_private_key_headers_in_paths_are_scanned_and_redacted_across_sources(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        key_header = "-----BEGIN OPEN" + "SSH PRIVATE KEY-----"
        sensitive_name = f"{key_header}.txt"
        findings = list(auditor.audit_bytes(sensitive_name, b"safe"))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / sensitive_name).write_text("safe", encoding="utf-8")
            findings.extend(auditor.audit_directory(root))

            repository = root / "repository"
            repository.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.name", "Audit Test"], cwd=repository, check=True)
            subprocess.run(
                ["git", "config", "user.email", "audit@example.test"], cwd=repository, check=True
            )
            (repository / sensitive_name).write_text("safe", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "path fixture"], cwd=repository, check=True)
            findings.extend(auditor.audit_git_history(repository))

        self.assertEqual(3, sum(finding.rule == "private-key" for finding in findings))
        rendered = "\n".join(f"{finding.path} {finding.detail}" for finding in findings)
        self.assertNotIn(key_header, rendered)

    def test_unquoted_credentials_in_source_are_not_exempted(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        unsafe = b"pass" + b"word = CorrectHorseBatteryStaple\ntoken = live-secret"
        findings = auditor.audit_bytes("settings.py", unsafe)
        self.assertGreaterEqual(
            sum(finding.rule == "credential-assignment" for finding in findings),
            2,
        )
        safe = b"pass" + b"word = <redacted>\ntoken = $env:GITHUB_TOKEN\nsecret = None"
        self.assertFalse(auditor.audit_bytes("example.ps1", safe))

    def test_content_audit_rejects_private_operation_identifiers_in_text(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        identifier = b"scripts/deploy" + b"-production.ps1"
        findings = auditor.audit_bytes("notes.txt", b"command=" + identifier)
        self.assertTrue(any(finding.rule == "private-operation-identifier" for finding in findings))

    def test_content_audit_accepts_an_explicit_synthetic_key_fixture(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        header = b"-----BEGIN OPEN" + b"SSH PRIVATE KEY-----"
        marker = b"\nPUBLIC_AUDIT_" + b"SYNTHETIC_KEY_FIXTURE\n"
        path = "tests/fixtures/public-audit-private-key.txt"
        self.assertFalse(auditor.audit_bytes(path, header + marker))

    def test_synthetic_key_fixture_does_not_mask_an_unmarked_key(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        header = b"-----BEGIN OPEN" + b"SSH PRIVATE KEY-----"
        marker = b"\nPUBLIC_AUDIT_" + b"SYNTHETIC_KEY_FIXTURE\n"
        data = header + marker + header + b"\nprivate material"
        findings = auditor.audit_bytes("tests/fixtures/public-audit-private-key.txt", data)
        self.assertTrue(any(finding.rule == "private-key" for finding in findings))

    def test_generic_fixture_words_and_test_paths_do_not_exempt_keys_or_unc_hosts(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        header = b"-----BEGIN OPEN" + b"SSH PRIVATE KEY-----"
        key_findings = auditor.audit_bytes(
            "tests/fixtures/public-audit-private-key.txt",
            header + b"\nfixture",
        )
        self.assertTrue(any(finding.rule == "private-key" for finding in key_findings))
        deployment_key = auditor.audit_bytes(
            "tests/test_deployment_scripts.py",
            header + b"\\nfixture",
        )
        self.assertTrue(any(finding.rule == "private-key" for finding in deployment_key))

        separator = b"\\" * 2
        known_synthetic = b"for unsafe in (" + separator + b"server\\share\\file):"
        self.assertFalse(auditor.audit_bytes("tests/test_util.py", known_synthetic))
        real_looking = b"path=" + separator + b"server\\Payroll$\\records"
        unc_findings = auditor.audit_bytes("tests/test_util.py", real_looking)
        self.assertTrue(any(finding.rule == "private-unc-host" for finding in unc_findings))

    def test_content_audit_rejects_sensitive_paths_and_symlinks(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "catalog.db").write_bytes(b"SQLite")
            (root / "safe.txt").write_text("safe", encoding="utf-8")
            symlink = root / "linked.txt"
            try:
                symlink.symlink_to(root / "safe.txt")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")

            findings = auditor.audit_directory(root)

            rules = {finding.rule for finding in findings}
            self.assertIn("sensitive-extension", rules)
            self.assertIn("symlink", rules)

    def test_directory_audit_scans_and_redacts_the_input_root_basename(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        key_header = "-----BEGIN OPEN" + "SSH PRIVATE KEY-----"
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            source = parent / f"{key_header}-source"
            source.mkdir()
            source_findings = auditor.audit_directory(source)

            linked_source = parent / f"{key_header}-linked"
            try:
                linked_source.symlink_to(source, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlinks unavailable")
            linked_findings = auditor.audit_directory(linked_source)

        for findings in (source_findings, linked_findings):
            self.assertEqual(1, sum(finding.rule == "private-key" for finding in findings))
            rendered = "\n".join(f"{finding.path} {finding.detail}" for finding in findings)
            self.assertNotIn(key_header, rendered)
        self.assertTrue(any(finding.rule == "symlink" for finding in linked_findings))

    def test_directory_audit_reports_each_real_git_directory_once_and_prunes_it(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root_git = parent / ".git"
            (root_git / "objects").mkdir(parents=True)
            (root_git / "objects" / "private.env").write_text(
                "pass" + "word=MustRemainPruned",
                encoding="utf-8",
            )

            scan_root = parent / "source"
            nested_git = scan_root / "nested" / ".git"
            (nested_git / "objects").mkdir(parents=True)
            (nested_git / "objects" / "private.env").write_text(
                "pass" + "word=MustAlsoRemainPruned",
                encoding="utf-8",
            )

            root_findings = auditor.audit_directory(root_git)
            nested_findings = auditor.audit_directory(scan_root)

        self.assertEqual(
            [(".git", "git-metadata")],
            [(finding.path, finding.rule) for finding in root_findings],
        )
        self.assertEqual(
            [("nested/.git", "git-metadata")],
            [(finding.path, finding.rule) for finding in nested_findings],
        )

    def test_zip_audit_rejects_traversal_symlinks_and_excessive_expansion(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "unsafe.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
                handle.writestr("../escape.txt", "escape")
                link = zipfile.ZipInfo("linked.txt")
                link.create_system = 3
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                handle.writestr(link, "target.txt")
                handle.writestr("expanded.txt", b"A" * (2 * 1024 * 1024))

            findings = auditor.audit_zip(archive, max_member_size=1024 * 1024)

            rules = {finding.rule for finding in findings}
            self.assertIn("unsafe-archive-path", rules)
            self.assertIn("symlink", rules)
            self.assertIn("archive-member-size", rules)

    def test_zip_audit_scans_and_redacts_archive_basename_before_open_failure(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        key_header = "-----BEGIN OPEN" + "SSH PRIVATE KEY-----"
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / f"{key_header}.zip"
            archive.write_bytes(b"not a ZIP archive")

            findings = auditor.audit_zip(archive)

        rules = {finding.rule for finding in findings}
        self.assertIn("private-key", rules)
        self.assertIn("invalid-archive", rules)
        rendered = "\n".join(f"{finding.path} {finding.detail}" for finding in findings)
        self.assertNotIn(key_header, rendered)

    def test_zip_audit_scans_private_key_paths_before_every_early_rejection(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        key_header = "-----BEGIN OPEN" + "SSH PRIVATE KEY-----"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archives: list[tuple[str, Path, str, int]] = []

            unsafe = root / "unsafe.zip"
            with zipfile.ZipFile(unsafe, "w") as handle:
                handle.writestr(f"../{key_header}.txt", b"safe")
            archives.append(("unsafe", unsafe, "unsafe-archive-path", 1))

            duplicate = root / "duplicate.zip"
            with zipfile.ZipFile(duplicate, "w") as handle:
                handle.writestr(f"{key_header}.txt", b"safe")
                handle.writestr(f"{key_header.casefold()}.txt", b"safe")
            archives.append(("duplicate", duplicate, "duplicate-archive-path", 2))

            symlink = root / "symlink.zip"
            link = zipfile.ZipInfo(f"{key_header}.link")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(symlink, "w") as handle:
                handle.writestr(link, "target.txt")
            archives.append(("symlink", symlink, "symlink", 1))

            encrypted = root / "encrypted.zip"
            with zipfile.ZipFile(encrypted, "w") as handle:
                handle.writestr(f"{key_header}.txt", b"safe")
            encrypted_bytes = bytearray(encrypted.read_bytes())
            for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
                header_offset = encrypted_bytes.index(signature)
                flags = int.from_bytes(
                    encrypted_bytes[header_offset + flag_offset : header_offset + flag_offset + 2],
                    "little",
                )
                encrypted_bytes[header_offset + flag_offset : header_offset + flag_offset + 2] = (
                    flags | 1
                ).to_bytes(2, "little")
            encrypted.write_bytes(encrypted_bytes)
            archives.append(("encrypted", encrypted, "encrypted-archive-member", 1))

            compressed = root / "compressed.zip"
            with zipfile.ZipFile(compressed, "w", compression=zipfile.ZIP_DEFLATED) as handle:
                handle.writestr(f"{key_header}.txt", b"A" * (2 * 1024 * 1024))
            archives.append(("compression-ratio", compressed, "archive-compression-ratio", 1))

            unreadable = root / "unreadable.zip"
            with zipfile.ZipFile(unreadable, "w", compression=zipfile.ZIP_STORED) as handle:
                handle.writestr(f"{key_header}.txt", b"safe")
            unreadable_bytes = bytearray(unreadable.read_bytes())
            local_header = unreadable_bytes.index(b"PK\x03\x04")
            name_length = int.from_bytes(unreadable_bytes[local_header + 26 : local_header + 28], "little")
            extra_length = int.from_bytes(unreadable_bytes[local_header + 28 : local_header + 30], "little")
            data_offset = local_header + 30 + name_length + extra_length
            unreadable_bytes[data_offset] ^= 0xFF
            unreadable.write_bytes(unreadable_bytes)
            archives.append(("read-error", unreadable, "archive-read-error", 1))

            for name, archive, rejection_rule, expected_key_findings in archives:
                with self.subTest(name=name):
                    findings = auditor.audit_zip(archive)
                    self.assertIn(rejection_rule, {finding.rule for finding in findings})
                    self.assertEqual(
                        expected_key_findings,
                        sum(finding.rule == "private-key" for finding in findings),
                    )
                    rendered = "\n".join(
                        f"{finding.path} {finding.detail}" for finding in findings
                    )
                    self.assertNotIn(key_header, rendered)

    def test_zip_audit_rejects_git_metadata(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "git-metadata.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(".git/config", b"repository metadata")

            findings = auditor.audit_zip(archive)

            self.assertTrue(any(finding.rule == "git-metadata" for finding in findings))

    def test_zip_audit_rejects_empty_git_metadata_directories(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "git-directory.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(".git/", b"")

            findings = auditor.audit_zip(archive)

            self.assertTrue(any(finding.rule == "git-metadata" for finding in findings))

    def test_zip_audit_does_not_expand_an_archive_over_the_total_budget(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "over-budget.zip"
            credential_payload = b"pass" + b"word=MustNotBeExpanded"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
                handle.writestr("payload.txt", credential_payload)

            findings = auditor.audit_zip(archive, max_total_size=1)

            rules = {finding.rule for finding in findings}
            self.assertIn("archive-total-size", rules)
            self.assertNotIn("credential-assignment", rules)

    def test_git_history_audit_finds_deleted_secret_without_checkout(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Audit Test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "audit@example.test"], cwd=root, check=True)
            secret_file = root / "old.env"
            secret_file.write_text("pass" + "word=HistoryOnlySecret", encoding="utf-8")
            subprocess.run(["git", "add", "old.env"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "add fixture"], cwd=root, check=True)
            secret_file.unlink()
            subprocess.run(["git", "add", "-u"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "remove fixture"], cwd=root, check=True)
            before = subprocess.run(
                ["git", "status", "--porcelain"], cwd=root, check=True, text=True, capture_output=True
            ).stdout

            findings = auditor.audit_git_history(root)

            after = subprocess.run(
                ["git", "status", "--porcelain"], cwd=root, check=True, text=True, capture_output=True
            ).stdout
            self.assertEqual(before, after)
            self.assertTrue(any(finding.rule == "credential-assignment" for finding in findings))
            self.assertFalse(any("HistoryOnlySecret" in finding.detail for finding in findings))

    def test_git_history_audit_scans_commit_messages(self) -> None:
        auditor = importlib.import_module("scripts.audit_public_content")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Audit Test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "audit@example.test"], cwd=root, check=True)
            (root / "safe.txt").write_text("safe", encoding="utf-8")
            subprocess.run(["git", "add", "safe.txt"], cwd=root, check=True)
            message = "pass" + "word=MessageOnlySecret"
            subprocess.run(["git", "commit", "-q", "-m", message], cwd=root, check=True)

            findings = auditor.audit_git_history(root)

            self.assertTrue(
                any(
                    finding.path.endswith(":<commit-message>")
                    and finding.rule == "credential-assignment"
                    for finding in findings
                )
            )
            self.assertFalse(any("MessageOnlySecret" in finding.detail for finding in findings))

    def test_git_history_cli_ignores_only_the_repository_root_git_directory(self) -> None:
        script = ROOT / "scripts" / "audit-public-content.py"
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.name", "Audit Test"], cwd=repository, check=True)
            subprocess.run(
                ["git", "config", "user.email", "audit@example.test"],
                cwd=repository,
                check=True,
            )
            (repository / "safe.txt").write_text("safe", encoding="utf-8")
            subprocess.run(["git", "add", "safe.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repository, check=True)

            ordinary = subprocess.run(
                [sys.executable, str(script), "."],
                cwd=repository,
                text=True,
                capture_output=True,
                check=False,
            )
            with_history = subprocess.run(
                [sys.executable, str(script), ".", "--git-history"],
                cwd=repository,
                text=True,
                capture_output=True,
                check=False,
            )

            uppercase_history = None
            case_symlink_history = None
            uppercase_git = repository / ".GIT"
            if not uppercase_git.exists():
                uppercase_git.mkdir()
                (uppercase_git / "config").write_text("safe", encoding="utf-8")
                uppercase_history = subprocess.run(
                    [sys.executable, str(script), ".", "--git-history"],
                    cwd=repository,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                (uppercase_git / "config").unlink()
                uppercase_git.rmdir()
                case_symlink = repository / ".Git"
                try:
                    case_symlink.symlink_to(repository / ".git", target_is_directory=True)
                except (OSError, NotImplementedError):
                    pass
                else:
                    case_symlink_history = subprocess.run(
                        [sys.executable, str(script), ".", "--git-history"],
                        cwd=repository,
                        text=True,
                        capture_output=True,
                        check=False,
                    )

            nested_git = repository / "nested" / ".git"
            nested_git.mkdir(parents=True)
            (nested_git / "config").write_text("safe", encoding="utf-8")
            nested_history = subprocess.run(
                [sys.executable, str(script), ".", "--git-history"],
                cwd=repository,
                text=True,
                capture_output=True,
                check=False,
            )
            subdirectory_history = subprocess.run(
                [sys.executable, str(script), ".", "--git-history"],
                cwd=repository / "nested",
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(1, ordinary.returncode, ordinary.stdout + ordinary.stderr)
        self.assertIn("git-metadata .git", ordinary.stdout)
        self.assertEqual(0, with_history.returncode, with_history.stdout + with_history.stderr)
        self.assertIn("audit passed: zero findings", with_history.stdout)
        if uppercase_history is not None:
            self.assertEqual(1, uppercase_history.returncode, uppercase_history.stdout + uppercase_history.stderr)
            self.assertIn("git-metadata .GIT", uppercase_history.stdout)
        if case_symlink_history is not None:
            self.assertEqual(
                1,
                case_symlink_history.returncode,
                case_symlink_history.stdout + case_symlink_history.stderr,
            )
            self.assertIn("symlink .Git", case_symlink_history.stdout)
        self.assertEqual(1, nested_history.returncode, nested_history.stdout + nested_history.stderr)
        self.assertIn("git-metadata nested/.git", nested_history.stdout)
        self.assertEqual(
            1,
            subdirectory_history.returncode,
            subdirectory_history.stdout + subdirectory_history.stderr,
        )
        self.assertIn("git-metadata .git", subdirectory_history.stdout)

    def test_git_history_cli_accepts_the_validated_linked_worktree_gitfile(self) -> None:
        script = ROOT / "scripts" / "audit-public-content.py"
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            primary = parent / "primary"
            linked = parent / "linked"
            primary.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=primary, check=True)
            subprocess.run(["git", "config", "user.name", "Audit Test"], cwd=primary, check=True)
            subprocess.run(
                ["git", "config", "user.email", "audit@example.test"],
                cwd=primary,
                check=True,
            )
            (primary / "safe.txt").write_text("safe", encoding="utf-8")
            subprocess.run(["git", "add", "safe.txt"], cwd=primary, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=primary, check=True)
            subprocess.run(
                ["git", "worktree", "add", "-q", "-b", "linked-audit", str(linked)],
                cwd=primary,
                check=True,
            )

            result = subprocess.run(
                [sys.executable, str(script), ".", "--git-history"],
                cwd=linked,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("audit passed: zero findings", result.stdout)
