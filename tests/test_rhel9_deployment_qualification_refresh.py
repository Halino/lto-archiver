from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from itertools import pairwise
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests import test_rhel9_deployment as deployment_tests
from tests import test_rhel9_live_verifier as live_tests


def _fixture_ancestor_metadata(value, path):
    # The shared temporary root is not a production authority directory. Only
    # this external fixture ancestor substitutes its writable permission bits;
    # private directory identities, modes and symlink types remain real.
    if path == Path(tempfile.gettempdir()):
        fields = {
            name: getattr(value, name) for name in dir(value) if name.startswith("st_")
        }
        fields["st_mode"] &= ~0o022
        return SimpleNamespace(**fields)
    return value


class QualificationRefreshHost(deployment_tests.FakeDeploymentHost):
    def install_qualification_attestation(self, request) -> None:
        self.calls.append("install-qualification-attestation")
        self.attestation_request = request
        if self.fail_at == "qualification-attestation":
            raise RuntimeError("injected qualification attestation failure")


class DeploymentQualificationRefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = deployment_tests.Rhel9DeploymentTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.temporary.cleanup)
        self.module = fixture.module
        self.request = fixture.request
        self.host = QualificationRefreshHost(self.module, fixture.root)

    def test_refresh_follows_verified_install_and_precedes_preflight_and_activation(
        self,
    ):
        result = self.module.deploy(self.request, self.host)

        self.assertEqual("deployed", result.status)
        calls = self.host.calls
        self.assertEqual(1, calls.count("install-qualification-attestation"))
        self.assertIs(self.request, self.host.attestation_request)
        ordered = (
            "create-verified-rollback",
            "install-release-packages",
            "install:driver.rpm",
            "verify-installed-driver",
            "install-qualification-attestation",
            "authenticated-preflight",
            "activate-complete-stack",
            "verify-live",
        )
        for before, after in pairwise(ordered):
            with self.subTest(before=before, after=after):
                self.assertLess(calls.index(before), calls.index(after))
        self.assertNotIn("restore-verified-rollback", calls)

    def test_refresh_failure_rolls_back_without_preflight_or_activation(self):
        self.host.fail_at = "qualification-attestation"

        result = self.module.deploy(self.request, self.host)

        self.assertEqual("rolled_back", result.status)
        calls = self.host.calls
        self.assertEqual(1, calls.count("install-qualification-attestation"))
        self.assertEqual(1, calls.count("restore-verified-rollback"))
        self.assertLess(
            calls.index("verify-installed-driver"),
            calls.index("install-qualification-attestation"),
        )
        self.assertLess(
            calls.index("install-qualification-attestation"),
            calls.index("restore-verified-rollback"),
        )
        self.assertNotIn("authenticated-preflight", calls)
        self.assertNotIn("activate-complete-stack", calls)
        self.assertNotIn("verify-live", calls)

    def test_unverified_installed_driver_cannot_refresh_attestation(self):
        self.host.driver_unchanged = False

        result = self.module.deploy(self.request, self.host)

        self.assertEqual("rolled_back", result.status)
        self.assertIn("verify-installed-driver", self.host.calls)
        self.assertNotIn("install-qualification-attestation", self.host.calls)
        self.assertNotIn("authenticated-preflight", self.host.calls)
        self.assertNotIn("activate-complete-stack", self.host.calls)
        self.assertIn("restore-verified-rollback", self.host.calls)


class QualificationRpmMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = deployment_tests._load_module()
        self.rows = (
            "/usr/bin/ltfs\t" + "a" * 64 + "\t100755\troot\troot\n"
            "/usr/bin/mkltfs\t" + "b" * 64 + "\t100750\troot\tlto-admin\n"
            "/usr/bin/ltfsck\t" + "c" * 64 + "\t100755\troot\troot\n"
            "/usr/bin/ltfs-info\t" + "d" * 64 + "\t100755\troot\troot\n"
        )

    def parser(self):
        parser = getattr(self.module, "_qualification_driver_tools", None)
        self.assertTrue(callable(parser), "candidate RPM metadata parser missing")
        return parser

    def test_exact_driver_metadata_keeps_restricted_mkltfs(self):
        self.assertEqual(
            {
                "ltfs": "a" * 64,
                "mkltfs": "b" * 64,
                "ltfsck": "c" * 64,
                "ltfs-info": "d" * 64,
            },
            self.parser()(self.rows),
        )

    def test_ambiguous_incomplete_or_untrusted_metadata_is_rejected(self):
        parse = self.parser()
        mutations = (
            self.rows + self.rows.splitlines(keepends=True)[0],
            "".join(self.rows.splitlines(keepends=True)[:-1]),
            self.rows.replace("100750\troot\tlto-admin", "100755\troot\troot"),
            self.rows.replace("/usr/bin/ltfs\t", "/usr/bin/../bin/ltfs\t"),
            self.rows.replace("a" * 64, "not-a-digest"),
            self.rows.replace("\troot\troot", "\tother\troot", 1),
            self.rows.rstrip("\n"),
            self.rows + "x" * (4 * 1024 * 1024),
        )
        for index, raw in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaises(self.module.DeploymentError),
            ):
                parse(raw)

    def test_pinned_file_hash_rejects_changed_bytes_and_symlinks(self):
        reader = getattr(self.module, "_qualification_file", None)
        self.assertTrue(callable(reader), "qualification pinned reader missing")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "tool"
            path.write_bytes(b"verified tool")
            path.chmod(0o755)
            digest = hashlib.sha256(b"verified tool").hexdigest()
            # The only substituted boundary is required deployment ownership;
            # descriptor identity, file type, mode, link count and hash are real.
            original_lstat = Path.lstat
            original_fstat = os.fstat

            def root_metadata(value):
                fields = {
                    name: getattr(value, name)
                    for name in dir(value)
                    if name.startswith("st_")
                }
                fields.update(st_uid=0, st_gid=0)
                return SimpleNamespace(**fields)

            with (
                patch.object(
                    self.module.os,
                    "fstat",
                    side_effect=lambda fd: root_metadata(original_fstat(fd)),
                ),
                patch.object(
                    Path,
                    "lstat",
                    lambda item: root_metadata(
                        _fixture_ancestor_metadata(original_lstat(item), item)
                    ),
                ),
            ):
                self.assertEqual(
                    b"verified tool",
                    reader(path, mode=0o755, gid=0, expected=digest),
                )
                path.write_bytes(b"substituted tool")
                with self.assertRaises(self.module.DeploymentError):
                    reader(path, mode=0o755, gid=0, expected=digest)
                link = Path(temporary) / "link"
                link.symlink_to(path)
                with self.assertRaises(self.module.DeploymentError):
                    reader(link, mode=0o755, gid=0, expected=digest)


class QualificationAttestationProducerTests(unittest.TestCase):
    """Real files/publication; only root ownership and RPM query are simulated."""

    def setUp(self):
        self.module = deployment_tests._load_module()
        self.live = live_tests._load_module()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.target = self.root / "qualification-artifacts.json"
        self.tools = {}
        self.digests = {}
        for name in ("ltfs", "mkltfs", "ltfsck", "ltfs-info", "fusermount", "mt"):
            path = self.root / "bin" / name
            path.parent.mkdir(exist_ok=True)
            path.parent.chmod(0o755)
            content = ("verified " + name).encode()
            path.write_bytes(content)
            path.chmod(
                0o4755 if name == "fusermount" else 0o750 if name == "mkltfs" else 0o755
            )
            self.tools[name] = path
            self.digests[name] = hashlib.sha256(content).hexdigest()
        self.old = {
            "schema": 2,
            "linux_tree_sha256": "1" * 64,
            "ltfs_tree_sha256": "2" * 64,
            "ltfs_rpm_sha256": "3" * 64,
            "tool_sha256": {**self.digests, "ltfs": "4" * 64},
        }
        self.target.write_bytes(self.canonical(self.old))
        self.target.chmod(0o400)
        self.old_bytes = self.target.read_bytes()
        source = self.root / "SOURCES/lto-archiver-0.11.27.tar.gz"
        source.parent.mkdir()
        source.parent.chmod(0o755)
        source.write_bytes(b"authenticated application source archive")
        self.source = source
        self.manifest = self.root / "SHA256SUMS"
        self.manifest.write_text(
            hashlib.sha256(source.read_bytes()).hexdigest()
            + "  SOURCES/lto-archiver-0.11.27.tar.gz\n"
        )
        self.rpm = self.root / "driver.rpm"
        self.rpm.write_bytes(b"authenticated driver rpm")
        self.provenance = self.root / "provenance.json"
        self.provenance.write_bytes(self.canonical({"source_archive_sha256": "5" * 64}))
        contract = dict.fromkeys(self.live._DRIVER_KEYS, "6" * 64)
        contract.update(
            schema=1,
            package_nevra=self.live._DRIVER_NEVRA,
            rpm_raw_sha256=hashlib.sha256(self.rpm.read_bytes()).hexdigest(),
            rpm_verify_policy_sha256=self.live._DRIVER_RPM_VERIFY_POLICY_SHA256,
            source_provenance_status="authenticated-release",
            source_provenance_evidence_sha256=hashlib.sha256(
                self.provenance.read_bytes()
            ).hexdigest(),
        )
        self.contract_path = self.root / "driver-contract.json"
        self.contract_path.write_bytes(self.canonical(contract))
        # Bootstrap rejects group-writable inputs independently of ownership.
        # Set actual authority modes explicitly, regardless of the test umask.
        for path in (
            source,
            self.manifest,
            self.rpm,
            self.provenance,
            self.contract_path,
        ):
            path.chmod(0o644)
        self.request = SimpleNamespace(
            application_manifest=self.manifest,
            driver_rpm=self.rpm,
            driver_input_contract=self.contract_path,
            expected_driver_input_sha256=hashlib.sha256(
                self.contract_path.read_bytes()
            ).hexdigest(),
        )
        self.host = object.__new__(self.module.SystemDeploymentHost)
        self.host._live = self.live
        self.host._live_host = SimpleNamespace(
            _config=SimpleNamespace(
                driver_source_provenance_evidence=self.provenance,
            )
        )
        self.host._qualification_manifest = (
            self.manifest,
            hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
        )
        self.host._qualification_driver = (
            self.rpm,
            self.contract_path,
            self.request.expected_driver_input_sha256,
        )
        self.commands = []

        def rpm_query(argv):
            self.commands.append(argv)
            self.assertEqual((Path("/usr/bin/rpm"), "-qp", "--qf"), argv[:3])
            self.assertEqual(self.rpm, argv[-1])
            rows = "".join(
                f"{self.tools[name]}\t{self.digests[name]}\t"
                + (
                    "100750\troot\tlto-admin\n"
                    if name == "mkltfs"
                    else "100755\troot\troot\n"
                )
                for name in ("ltfs", "mkltfs", "ltfsck", "ltfs-info")
            )
            return subprocess.CompletedProcess(argv, 0, rows, "")

        self.host._run = rpm_query
        self.enterContext(
            patch.object(self.module, "_QUALIFICATION_ATTESTATION", self.target)
        )
        self.enterContext(patch.object(self.module, "_QUALIFICATION_TOOLS", self.tools))
        original_fstat = os.fstat
        original_lstat = Path.lstat

        def root_metadata(value):
            fields = {
                name: getattr(value, name)
                for name in dir(value)
                if name.startswith("st_")
            }
            fields.update(st_uid=0, st_gid=0)
            return SimpleNamespace(**fields)

        self.enterContext(
            patch.object(
                self.module.os,
                "fstat",
                side_effect=lambda fd: root_metadata(original_fstat(fd)),
            )
        )
        self.enterContext(
            patch.object(
                Path,
                "lstat",
                lambda path: root_metadata(
                    _fixture_ancestor_metadata(original_lstat(path), path)
                ),
            )
        )
        self.enterContext(
            patch.object(
                self.module.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=0)
            )
        )
        self.enterContext(
            patch.object(
                self.module.os,
                "fchown",
                side_effect=lambda fd, uid, gid: self.assertEqual((0, 0), (uid, gid)),
            )
        )

    @staticmethod
    def canonical(value):
        return (
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()

    def test_producer_publishes_source_archive_and_bound_six_tool_hashes(self):
        self.host.install_qualification_attestation(self.request)
        expected = {
            "schema": 2,
            "linux_tree_sha256": hashlib.sha256(
                b"authenticated application source archive"
            ).hexdigest(),
            "ltfs_tree_sha256": "5" * 64,
            "ltfs_rpm_sha256": hashlib.sha256(b"authenticated driver rpm").hexdigest(),
            "tool_sha256": self.digests,
        }
        self.assertEqual(self.canonical(expected), self.target.read_bytes())
        self.assertEqual(0o400, stat.S_IMODE(self.target.stat().st_mode))
        self.assertEqual(1, self.target.stat().st_nlink)
        self.assertEqual(1, len(self.commands))
        self.assertEqual([], list(self.root.glob(".qualification-*")))

    def test_unverified_inputs_cannot_publish(self):
        for name in ("_qualification_manifest", "_qualification_driver"):
            saved = getattr(self.host, name)
            setattr(self.host, name, None)
            try:
                with (
                    self.subTest(pin=name),
                    self.assertRaises(self.module.DeploymentError),
                ):
                    self.host.install_qualification_attestation(self.request)
            finally:
                setattr(self.host, name, saved)
            self.assertEqual(self.old_bytes, self.target.read_bytes())
        self.assertEqual([], self.commands)

    def test_changed_provenance_source_rpm_or_aux_tool_preserves_authority(self):
        cases = (
            (self.provenance, "qualification driver provenance changed", 0),
            (self.source, "artifact manifest member drifted", 0),
            (self.rpm, "qualification driver RPM changed", 0),
            (self.tools["mt"], "qualification file hash is invalid", 1),
            (self.tools["fusermount"], "qualification file hash is invalid", 1),
        )
        for path, error, queries in cases:
            self.commands.clear()
            original = path.read_bytes()
            path.write_bytes(b"untrusted replacement")
            if path == self.tools["fusermount"]:
                path.chmod(0o4755)
            try:
                with (
                    self.subTest(path=path.name),
                    self.assertRaisesRegex(self.module.DeploymentError, error),
                ):
                    self.host.install_qualification_attestation(self.request)
            finally:
                path.write_bytes(original)
                if path == self.tools["fusermount"]:
                    path.chmod(0o4755)
            self.assertEqual(self.old_bytes, self.target.read_bytes())
            self.assertEqual(queries, len(self.commands))

    def test_float_schema_cannot_authorize_publication(self):
        malformed = self.canonical({**self.old, "schema": 2.0})
        self.target.chmod(0o600)
        self.target.write_bytes(malformed)
        self.target.chmod(0o400)
        with self.assertRaisesRegex(
            self.module.DeploymentError,
            "qualification existing authority is not closed",
        ):
            self.host.install_qualification_attestation(self.request)
        self.assertEqual(malformed, self.target.read_bytes())
        self.assertEqual(1, len(self.commands))

    def test_symlinked_tool_parent_cannot_be_reblessed(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root / "bin", target_is_directory=True)
        self.tools["mt"] = alias / "mt"
        with self.assertRaises(self.module.DeploymentError):
            self.host.install_qualification_attestation(self.request)
        self.assertEqual(self.old_bytes, self.target.read_bytes())

    def test_writable_tool_parent_cannot_be_reblessed(self):
        directory = self.tools["mt"].parent
        directory.chmod(0o775)
        with self.assertRaisesRegex(
            self.module.DeploymentError, "qualification file ancestor is unsafe"
        ):
            self.host.install_qualification_attestation(self.request)
        self.assertEqual(self.old_bytes, self.target.read_bytes())
