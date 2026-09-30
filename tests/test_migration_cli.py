"""Public contract tests for the offline Windows-to-Linux migration CLI."""

from __future__ import annotations

import contextlib
import gc
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
import warnings
from pathlib import Path
from unittest import mock

from ltobackup.catalog import SCHEMA_VERSION, Catalog
from tests import test_migration_normalizer as normalizer_test_module
from tests.fixtures import build_frozen_job_fixture
from tests.test_migration_import import _canonical_bundle_for_catalog


class MigrationCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = Path(__file__).resolve().parents[1]
        self.python = Path(sys.executable)
        self.catalog = build_frozen_job_fixture(
            self.root / "windows.db", schema_version=13
        )
        self.bundle = _canonical_bundle_for_catalog(
            self.catalog, self.root / "canonical.zip"
        )
        self.source_root = self.root / "linux-source"
        self.source_root.mkdir()
        self.mapping = self.root / "mapping.json"
        self.mapping.write_text(
            json.dumps(
                {
                    "library_roots": {
                        str(self.root / "source-lib1"): str(self.source_root)
                    },
                    "device_names": {
                        "synthetic-drive": "/dev/tape/by-id/synthetic-drive"
                    },
                    "mount_paths": {"/synthetic/mount": "/mnt/lto-archiver/tape"},
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(
            filter(
                None,
                (str(self.repository / "src"), environment.get("PYTHONPATH")),
            )
        )
        return subprocess.run(
            [
                str(self.python),
                "-m",
                "ltobackup.migration.cli",
                *arguments,
            ],
            cwd=self.repository,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_inspect_reports_exact_frozen_boundary_without_sensitive_values(
        self,
    ) -> None:
        result = self.run_cli("inspect", str(self.bundle), "--json")

        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(
            {
                "accepted",
                "assignment_sha256",
                "bundle_sha256",
                "catalog_sha256",
                "completed_sequences",
                "error_codes",
                "media_accesses",
                "next_sequence",
                "total_cassettes",
            },
            set(payload),
        )
        self.assertTrue(payload["accepted"])
        self.assertEqual(4, payload["next_sequence"])
        self.assertEqual(20, payload["total_cassettes"])
        self.assertEqual([1, 2, 3], payload["completed_sequences"])
        self.assertEqual([], payload["media_accesses"])
        self.assertEqual([], payload["error_codes"])
        self.assertEqual("", result.stderr)
        self.assertNotIn(str(self.root), result.stdout)
        self.assertNotIn("JOB-MIGRATION", result.stdout)

    def test_normalize_preserves_capture_and_reports_verified_bundle(self) -> None:
        fixture = normalizer_test_module.MigrationNormalizerTests()
        fixture.root = self.root
        capture = self.root / "sealed-capture.tar.gz"
        fixture._write_members(capture, fixture._valid_members())
        before = capture.read_bytes()
        digest = hashlib.sha256(before).hexdigest()
        destination = self.root / "normalized.zip"

        result = self.run_cli(
            "normalize",
            str(capture),
            "--expected-sha256",
            digest,
            "--output",
            str(destination),
            "--json",
        )

        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["accepted"])
        self.assertEqual(4, payload["next_sequence"])
        self.assertEqual([], payload["media_accesses"])
        self.assertEqual(before, capture.read_bytes())
        self.assertTrue(destination.is_file())
        self.assertNotIn(str(capture), result.stdout + result.stderr)
        self.assertNotIn(str(destination), result.stdout + result.stderr)

    def test_import_activates_current_schema_and_persists_safe_receipt(self) -> None:
        state = self.root / "linux-state"
        bundle_before = self.bundle.read_bytes()
        mapping_before = self.mapping.read_bytes()

        result = self.run_cli(
            "import",
            str(self.bundle),
            "--mapping-file",
            str(self.mapping),
            "--state-dir",
            str(state),
            "--json",
        )

        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["accepted"])
        self.assertEqual(SCHEMA_VERSION, payload["activated_schema_version"])
        self.assertEqual("pre_cutover", payload["authority_state"])
        self.assertEqual("frozen-allocation", payload["policy_kind"])
        self.assertEqual("resumable", payload["windows_authority"])
        self.assertTrue(payload["rollback_allowed"])
        self.assertTrue(payload["acceptance_receipt_stored"])
        self.assertRegex(payload["job_id_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(payload["mapping_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(4, payload["next_sequence"])
        self.assertEqual([], payload["media_accesses"])
        self.assertNotIn(str(self.root), result.stdout + result.stderr)
        self.assertNotIn("JOB-MIGRATION", result.stdout + result.stderr)
        self.assertEqual(bundle_before, self.bundle.read_bytes())
        self.assertEqual(mapping_before, self.mapping.read_bytes())
        receipt_path = state / "migrations" / "windows-import-acceptance.json"
        self.assertTrue(receipt_path.is_file())
        self.assertEqual(0o600, receipt_path.stat().st_mode & 0o777)
        receipt = json.loads(receipt_path.read_text(encoding="ascii"))
        self.assertEqual(payload, receipt)
        with Catalog(state / "catalog.db") as catalog:
            policy = catalog.get_import_policy("JOB-MIGRATION")
        self.assertEqual("pre_cutover", policy.authority_state)
        self.assertTrue(policy.rollback_allowed)

    def test_matching_import_retry_is_idempotent_but_changed_mapping_is_rejected(
        self,
    ) -> None:
        state = self.root / "idempotent-state"
        arguments = (
            "import",
            str(self.bundle),
            "--mapping-file",
            str(self.mapping),
            "--state-dir",
            str(state),
            "--json",
        )
        first = self.run_cli(*arguments)
        second = self.run_cli(*arguments)

        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertEqual(first.stdout, second.stdout)

        changed = json.loads(self.mapping.read_text(encoding="utf-8"))
        changed["device_names"]["synthetic-drive"] = "/dev/tape/by-id/other-drive"
        self.mapping.write_text(json.dumps(changed), encoding="utf-8")
        rejected = self.run_cli(*arguments)
        self.assertEqual(2, rejected.returncode)
        self.assertEqual("migration rejected\n", rejected.stderr)

    def test_receipt_write_failure_never_leaves_activated_state(self) -> None:
        from ltobackup.migration import cli

        state = self.root / "receipt-failure-state"
        stdout = io.StringIO()
        stderr = io.StringIO()
        gc.collect()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            with (
                mock.patch.object(
                    cli.importer_module,
                    "_write_acceptance_receipt",
                    side_effect=OSError("injected receipt failure"),
                    create=True,
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                returncode = cli.main(
                    [
                        "import",
                        str(self.bundle),
                        "--mapping-file",
                        str(self.mapping),
                        "--state-dir",
                        str(state),
                        "--json",
                    ]
                )
            gc.collect()

        self.assertEqual(3, returncode)
        self.assertFalse(state.exists())
        self.assertEqual(
            ["runtime-failure"], json.loads(stdout.getvalue())["error_codes"]
        )
        self.assertEqual("migration failed\n", stderr.getvalue())
        self.assertEqual(
            [],
            [
                item
                for item in caught
                if isinstance(item.message, ResourceWarning)
                and "unclosed database" in str(item.message)
            ],
        )

    def test_import_rejects_missing_mapping_and_existing_state_deterministically(
        self,
    ) -> None:
        missing = self.run_cli(
            "import", str(self.bundle), "--state-dir", str(self.root / "state")
        )
        self.assertEqual(2, missing.returncode)
        self.assertEqual(
            ["invalid-arguments"], json.loads(missing.stdout)["error_codes"]
        )
        self.assertEqual("migration rejected\n", missing.stderr)

        state = self.root / "occupied-state"
        state.mkdir()
        marker = state / "preserve"
        marker.write_text("operator data", encoding="utf-8")
        occupied = self.run_cli(
            "import",
            str(self.bundle),
            "--mapping-file",
            str(self.mapping),
            "--state-dir",
            str(state),
        )
        self.assertEqual(2, occupied.returncode)
        self.assertIn("state-not-empty", json.loads(occupied.stdout)["error_codes"])
        self.assertEqual("operator data", marker.read_text(encoding="utf-8"))
        self.assertNotIn(str(state), occupied.stdout + occupied.stderr)

    def test_mapping_document_is_nofollow_bounded_and_exact(self) -> None:
        extra = self.root / "extra.json"
        extra.write_text(
            json.dumps(
                {
                    "library_roots": {},
                    "device_names": {},
                    "mount_paths": {},
                    "credentials": "must-not-be-admitted",
                }
            ),
            encoding="utf-8",
        )
        rejected = self.run_cli(
            "import",
            str(self.bundle),
            "--mapping-file",
            str(extra),
            "--state-dir",
            str(self.root / "extra-state"),
        )
        self.assertEqual(2, rejected.returncode)
        self.assertEqual(
            ["mapping-invalid"], json.loads(rejected.stdout)["error_codes"]
        )
        self.assertNotIn("credentials", rejected.stdout + rejected.stderr)

        linked = self.root / "mapping-link.json"
        linked.symlink_to(self.mapping)
        nofollow = self.run_cli(
            "import",
            str(self.bundle),
            "--mapping-file",
            str(linked),
            "--state-dir",
            str(self.root / "linked-state"),
        )
        self.assertEqual(2, nofollow.returncode)
        self.assertEqual(
            ["mapping-not-regular"], json.loads(nofollow.stdout)["error_codes"]
        )

        oversized = self.root / "oversized.json"
        oversized.write_bytes(b" " * (1024 * 1024 + 1))
        bounded = self.run_cli(
            "import",
            str(self.bundle),
            "--mapping-file",
            str(oversized),
            "--state-dir",
            str(self.root / "oversized-state"),
        )
        self.assertEqual(2, bounded.returncode)
        self.assertEqual(
            ["mapping-size-limit"], json.loads(bounded.stdout)["error_codes"]
        )

        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            '{"library_roots":{},"library_roots":{},'
            '"device_names":{},"mount_paths":{}}',
            encoding="utf-8",
        )
        duplicate_result = self.run_cli(
            "import",
            str(self.bundle),
            "--mapping-file",
            str(duplicate),
            "--state-dir",
            str(self.root / "duplicate-state"),
        )
        self.assertEqual(2, duplicate_result.returncode)
        self.assertEqual(
            ["mapping-invalid"],
            json.loads(duplicate_result.stdout)["error_codes"],
        )

    def test_mapping_rejects_unicode_format_controls_before_path_resolution(
        self,
    ) -> None:
        controlled = self.root / "controlled.json"
        controlled.write_text(
            json.dumps(
                {
                    "library_roots": {
                        str(self.root / "source-lib1"): "/safe/\u202esecret"
                    },
                    "device_names": {
                        "synthetic-drive": "/dev/tape/by-id/synthetic-drive"
                    },
                    "mount_paths": {"/synthetic/mount": "/mnt/lto-archiver/tape"},
                }
            ),
            encoding="utf-8",
        )

        result = self.run_cli(
            "import",
            str(self.bundle),
            "--mapping-file",
            str(controlled),
            "--state-dir",
            str(self.root / "controlled-state"),
        )

        self.assertEqual(2, result.returncode)
        self.assertEqual(["mapping-invalid"], json.loads(result.stdout)["error_codes"])
        self.assertNotIn("secret", result.stdout + result.stderr)

    def test_mapping_rejects_same_inode_mutation_with_restored_size_and_mtime(
        self,
    ) -> None:
        from ltobackup.migration import cli

        original = self.mapping.read_bytes()
        replacement = original.replace(b"linux-source", b"linux-sourcf")
        self.assertEqual(len(original), len(replacement))
        original_stat = self.mapping.stat()
        real_fstat = os.fstat
        calls = 0

        def mutate_after_first_stat(descriptor: int):
            nonlocal calls
            details = real_fstat(descriptor)
            calls += 1
            if calls == 1:
                with self.mapping.open("r+b") as stream:
                    stream.write(replacement)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.utime(
                    self.mapping,
                    ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
                )
                changed = self.mapping.stat()
                self.assertEqual(original_stat.st_ino, changed.st_ino)
                self.assertEqual(original_stat.st_size, changed.st_size)
                self.assertEqual(original_stat.st_mtime_ns, changed.st_mtime_ns)
                self.assertNotEqual(original_stat.st_ctime_ns, changed.st_ctime_ns)
            return details

        with (
            mock.patch.object(cli.os, "fstat", side_effect=mutate_after_first_stat),
            self.assertRaisesRegex(
                cli.MigrationRejected, "mapping-changed-during-read"
            ),
        ):
            cli._read_mapping_bytes(self.mapping)

    def test_rejection_and_runtime_failure_are_json_and_redacted(self) -> None:
        corrupt = self.root / "private-customer-label.zip"
        corrupt.write_bytes(b"not a canonical bundle")
        rejected = self.run_cli("inspect", str(corrupt), "--json")
        self.assertEqual(2, rejected.returncode)
        self.assertFalse(json.loads(rejected.stdout)["accepted"])
        self.assertEqual("migration rejected\n", rejected.stderr)
        self.assertNotIn(str(corrupt), rejected.stdout + rejected.stderr)

        from ltobackup.migration import cli

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                cli,
                "read_bundle",
                side_effect=RuntimeError("credential=/secret/path media=TAPE04"),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = cli.main(["inspect", str(self.bundle), "--json"])
        self.assertEqual(3, returncode)
        self.assertEqual(
            ["runtime-failure"], json.loads(stdout.getvalue())["error_codes"]
        )
        self.assertEqual("migration failed\n", stderr.getvalue())
        self.assertNotIn("secret", stdout.getvalue() + stderr.getvalue())
        self.assertNotIn("TAPE04", stdout.getvalue() + stderr.getvalue())

    def test_entry_point_is_packaged(self) -> None:
        with (self.repository / "pyproject.toml").open("rb") as stream:
            configuration = tomllib.load(stream)
        self.assertEqual(
            "ltobackup.migration.cli:main",
            configuration["project"]["scripts"]["lto-archiver-migrate"],
        )


if __name__ == "__main__":
    unittest.main()
