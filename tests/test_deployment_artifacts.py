"""Retention contracts use real private bundle trees and durable evidence files."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "packaging/scripts/deployment_artifacts.py"


class DeploymentArtifactTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "deployment artifact retention is not implemented")
        spec = importlib.util.spec_from_file_location("deployment_artifacts_under_test", SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.module
        spec.loader.exec_module(self.module)
        # Root authority is substituted only for isolated, current-user test files.
        for name, value in (("_ROOT_UID", os.getuid()), ("_ROOT_GID", os.getgid())):
            patcher = mock.patch.object(self.module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        temporary = tempfile.TemporaryDirectory(prefix="deployment-artifacts-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.registry_path = self.root / "registry"
        self.registry = self.module.DeploymentArtifactRegistry(self.registry_path)
        self.expected = {}

    def bundle(self, name):
        path = self.root / name / "rollback-bundles" / "predecessor-schema40"
        path.mkdir(parents=True, mode=0o700)
        data = json.dumps({"schema": 4, "bundle_id": name}).encode()
        manifest = path / "bundle-manifest.json"
        manifest.write_bytes(data)
        manifest.chmod(0o600)
        payload = path / "protected-catalog.sqlite3"
        payload.write_bytes(b"preserved predecessor catalog " + name.encode())
        payload.chmod(0o600)
        digest = hashlib.sha256(data).hexdigest()
        self.expected[str(path)] = {p.name: p.read_bytes() for p in path.iterdir()}
        return path, digest

    def verify(self, path):
        expected = self.expected[str(path)]
        actual = {p.relative_to(path).as_posix(): p.read_bytes()
                  for p in path.rglob("*") if p.is_file()}
        if actual != expected:
            raise RuntimeError("sealed bundle verification failed")

    @staticmethod
    def prove_prunable(path):
        # Host reference/lease observations are a required external proof seam.
        # Tests below replace this with an explicit refusal, never a bool permit.
        if not path.is_dir():
            raise RuntimeError("bundle disappeared")

    def register(self, bundle):
        path, digest = bundle
        self.registry.register_verified_bundle(path, digest, verify_bundle=self.verify)

    def evidence(self, bundle, *, status="deployed"):
        path, digest = bundle
        evidence = self.root / (path.parents[1].name + "-deployment.json")
        data = json.dumps({
            "schema": 1, "status": status, "rollback_manifest_sha256": digest,
            "repository_commit": "a" * 40, "application_manifest_sha256": "b" * 64,
            "application_rpm_sha256": "c" * 64, "driver_input_sha256": "d" * 64,
            "live_report_sha256": "e" * 64, "runtime_manifest_sha256": "f" * 64,
            "runtime_rpm_sha256": "0" * 64,
        }).encode()
        evidence.write_bytes(data)
        evidence.chmod(0o600)
        return evidence, hashlib.sha256(data).hexdigest()

    def promote(self, bundle, *, proof=None, evidence=None):
        evidence_path, evidence_sha256 = evidence or self.evidence(bundle)
        return self.registry.promote_after_success(
            bundle[0], evidence_path=evidence_path, evidence_sha256=evidence_sha256,
            verify_bundle=self.verify,
            prove_prunable=self.prove_prunable if proof is None else proof,
        )

    def established(self):
        old, new = self.bundle("old"), self.bundle("new")
        self.register(old)
        self.assertEqual("promoted", self.promote(old)["status"])
        self.register(new)
        return old, new

    def test_registration_never_prunes_last_successful_rollback(self):
        old, new = self.established()
        self.assertTrue(old[0].is_dir())
        self.assertTrue(new[0].is_dir())

    def test_registered_but_never_successful_deployment_is_not_superseded(self):
        abandoned = self.bundle("abandoned")
        self.register(abandoned)
        old, new = self.established()
        result = self.promote(new)
        self.assertEqual([str(old[0])], result["pruned"])
        self.assertTrue(abandoned[0].is_dir())

    def test_success_prunes_only_registered_superseded_bundle_and_survives_restart(self):
        old, new = self.established()
        unknown = self.bundle("unknown")[0]
        stage_file = old[0].parents[1] / "source-build-must-stay"
        stage_file.write_bytes(b"unknown staging ownership")
        self.registry = self.module.DeploymentArtifactRegistry(self.registry_path)
        result = self.promote(new)
        self.assertEqual("promoted", result["status"])
        self.assertEqual([str(old[0])], result["pruned"])
        self.assertFalse(old[0].exists())
        self.assertTrue(new[0].is_dir())
        self.assertTrue(unknown.is_dir())
        self.assertEqual(b"unknown staging ownership", stage_file.read_bytes())

    def test_repeated_prunes_retain_compact_tombstones_and_live_inventories(self):
        untouched = self.bundle("registered-only")
        self.register(untouched)
        previous = None
        retired = []
        for name in ("release-one", "release-two", "release-three"):
            current = self.bundle(name)
            self.register(current)
            self.assertEqual("promoted", self.promote(current)["status"])
            if previous is not None:
                retired.append(previous)
            self.registry = self.module.DeploymentArtifactRegistry(self.registry_path)
            state = json.loads((self.registry_path / "registry.json").read_text())
            for bundle in retired:
                tombstone = state["bundles"][str(bundle[0])]
                self.assertEqual("pruned", tombstone["state"])
                self.assertEqual(bundle[1], tombstone["manifest_sha256"])
                self.assertNotIn("inventory", tombstone)
                self.assertFalse(bundle[0].exists())
            self.assertTrue(state["bundles"][str(current[0])]["inventory"])
            self.assertTrue(state["bundles"][str(untouched[0])]["inventory"])
            previous = current

    def test_failed_deployment_evidence_preserves_both_bundles(self):
        old, new = self.established()
        result = self.promote(new, evidence=self.evidence(new, status="rolled_back"))
        self.assertEqual("refused", result["status"])
        self.assertTrue(old[0].is_dir())
        self.assertTrue(new[0].is_dir())

    def test_wrong_evidence_binding_cannot_promote(self):
        old, new = self.established()
        result = self.promote(new, evidence=self.evidence(old))
        self.assertEqual("refused", result["status"])
        self.assertTrue(old[0].is_dir())

    def test_changed_success_evidence_cannot_promote(self):
        old, new = self.established()
        evidence, digest = self.evidence(new)
        evidence.write_bytes(evidence.read_bytes() + b" ")
        result = self.promote(new, evidence=(evidence, digest))
        self.assertEqual("refused", result["status"])
        self.assertTrue(old[0].is_dir())

    def test_new_bundle_corruption_never_releases_previous_rollback(self):
        old, new = self.established()
        (new[0] / "protected-catalog.sqlite3").write_bytes(b"corrupt")
        result = self.promote(new)
        self.assertEqual("refused", result["status"])
        self.assertTrue(old[0].is_dir())

    def test_replaced_old_directory_is_unknown_and_retained(self):
        old, new = self.established()
        retained = old[0].with_name("original-retained")
        old[0].rename(retained)
        old[0].mkdir(mode=0o700)
        (old[0] / "foreign").write_bytes(b"not owned by registry")
        result = self.promote(new)
        self.assertEqual("promoted", result["status"])
        self.assertTrue(old[0].is_dir())
        self.assertTrue(retained.is_dir())
        self.assertTrue(result["deferred"])

    def test_changed_old_payload_is_retained(self):
        old, new = self.established()
        (old[0] / "protected-catalog.sqlite3").write_bytes(b"foreign changes")
        result = self.promote(new)
        self.assertEqual("promoted", result["status"])
        self.assertTrue(old[0].is_dir())
        self.assertTrue(result["deferred"])

    def test_live_reference_or_lease_refusal_keeps_old_and_new(self):
        old, new = self.established()

        def busy(path):
            raise RuntimeError("open rollback reference or active lease")

        result = self.promote(new, proof=busy)
        self.assertEqual("promoted", result["status"])
        self.assertTrue(result["deferred"])
        self.assertTrue(old[0].is_dir())
        self.assertTrue(new[0].is_dir())

    def test_boolean_proof_is_not_authority_to_delete(self):
        old, new = self.established()
        result = self.promote(new, proof=lambda path: True)
        self.assertEqual("promoted", result["status"])
        self.assertTrue(old[0].is_dir())
        self.assertTrue(result["deferred"])

    def test_historical_bundle_does_not_require_current_predecessor_compatibility(self):
        old, new = self.established()
        evidence, digest = self.evidence(new)

        def current_release_verifier(path):
            if path != new[0]:
                raise RuntimeError("historical predecessor is not the current release pair")
            self.verify(path)

        result = self.registry.promote_after_success(
            new[0], evidence_path=evidence, evidence_sha256=digest,
            verify_bundle=current_release_verifier, prove_prunable=self.prove_prunable,
        )
        self.assertEqual("promoted", result["status"])
        self.assertFalse(old[0].exists())
        self.assertTrue(new[0].is_dir())

    def test_registry_failure_after_deployment_is_observable_and_nonthrowing(self):
        old, new = self.established()
        evidence = self.evidence(new)
        # Refuse durable registry writes at their real filesystem boundary.
        with mock.patch.object(self.module.os, "replace", side_effect=OSError("disk full")):
            result = self.promote(new, evidence=evidence)
        self.assertEqual("refused", result["status"])
        self.assertTrue(result["error"])
        self.assertTrue(old[0].is_dir())
        self.assertTrue(new[0].is_dir())

    def test_prune_io_failure_keeps_durable_new_rollback_and_reports_partial_cleanup(self):
        old, new = self.established()
        real_unlink = self.module.os.unlink

        def fail_payload(path, *args, **kwargs):
            if path == "protected-catalog.sqlite3":
                raise OSError("injected prune I/O failure")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(self.module.os, "unlink", side_effect=fail_payload):
            result = self.promote(new)
        self.assertEqual("promoted", result["status"])
        self.assertTrue(result["deferred"])
        self.assertTrue(new[0].is_dir())
        self.verify(new[0])
        self.registry = self.module.DeploymentArtifactRegistry(self.registry_path)
        with self.registry.lease(new[0]):
            self.verify(new[0])
        self.assertTrue((old[0] / "protected-catalog.sqlite3").is_file())
        # The durable pruning record must recover after a transient failure;
        # missing entries removed by the prior attempt do not orphan the rest.
        result = self.promote(new)
        self.assertEqual([str(old[0])], result["pruned"])
        self.assertFalse(old[0].exists())
        self.verify(new[0])

    @contextmanager
    def observed_owners(self, paths, uid=990, gid=989):
        """Model service-owned snapshot stat results without root test privileges."""
        identities = {(p.stat().st_dev, p.stat().st_ino) for p in paths}
        real_stat, real_fstat = self.module.os.stat, self.module.os.fstat

        def substitute(details):
            if (details.st_dev, details.st_ino) not in identities:
                return details
            fields = {name: getattr(details, name) for name in dir(details)
                      if name.startswith("st_")}
            return SimpleNamespace(**{**fields, "st_uid": uid, "st_gid": gid})

        with mock.patch.object(self.module.os, "stat", side_effect=lambda *a, **kw: substitute(real_stat(*a, **kw))), \
             mock.patch.object(self.module.os, "fstat", side_effect=lambda *a, **kw: substitute(real_fstat(*a, **kw))):
            yield

    def test_verified_snapshot_retains_service_owner_and_original_modes(self):
        old = self.bundle("service-snapshot")
        snapshots = old[0] / "snapshots"
        snapshots.mkdir(mode=0o700)
        source = snapshots / "application_state"
        source.mkdir(mode=0o750)
        payload = source / "catalog.db"
        payload.write_bytes(b"catalog with preserved source metadata")
        payload.chmod(0o660)
        self.expected[str(old[0])]["snapshots/application_state/catalog.db"] = payload.read_bytes()
        with self.observed_owners((source, payload)):
            self.register(old)
            self.assertEqual("promoted", self.promote(old)["status"])
            with self.registry.lease(old[0]):
                self.assertEqual(0o660, payload.stat().st_mode & 0o777)
                self.assertEqual(990, payload.stat().st_uid)
            new = self.bundle("after-service-snapshot")
            self.register(new)
            result = self.promote(new)
            self.assertEqual([str(old[0])], result["pruned"])
        self.assertTrue(new[0].is_dir())

    def test_service_owned_snapshots_container_cannot_authorize_retention(self):
        bundle = self.bundle("unsealed-snapshots")
        snapshots = bundle[0] / "snapshots"
        snapshots.mkdir(mode=0o700)
        with self.observed_owners((snapshots,)), self.assertRaises(self.module.RetentionError):
            self.register(bundle)

    def test_optional_lease_for_legacy_bundle_does_not_create_registry(self):
        legacy = self.bundle("legacy")
        self.assertFalse(self.registry_path.exists())
        with self.registry.lease_if_registered(legacy[0]):
            self.verify(legacy[0])
        self.assertFalse(self.registry_path.exists())

    def test_optional_lease_preserves_unknown_entry_without_registering_it(self):
        old, new = self.established()
        legacy = self.bundle("legacy")
        before = (self.registry_path / "registry.json").read_bytes()
        with self.registry.lease_if_registered(legacy[0]):
            self.verify(legacy[0])
        self.assertEqual(before, (self.registry_path / "registry.json").read_bytes())
        self.assertTrue(old[0].is_dir())
        self.assertTrue(new[0].is_dir())

    def test_optional_registered_lease_blocks_promotion(self):
        old, new = self.established()
        with self.registry.lease_if_registered(old[0]):
            result = self.promote(new)
        self.assertEqual("refused", result["status"])
        self.assertTrue(old[0].is_dir())

    def test_optional_lease_does_not_swallow_corruption_or_changed_owned_bundle(self):
        old, _new = self.established()
        payload = old[0] / "protected-catalog.sqlite3"
        payload.write_bytes(b"changed")
        with self.assertRaises(self.module.RetentionError), self.registry.lease_if_registered(old[0]):
            self.fail("changed registered bundle admitted")
        (self.registry_path / "registry.json").write_text("invalid json")
        with self.assertRaises(self.module.RetentionError), self.registry.lease_if_registered(old[0]):
            self.fail("corrupt registry ignored")

    def test_completed_prune_converges_after_final_registry_write_failure(self):
        old, new = self.established()
        real_replace = self.module.os.replace

        def fail_after_delete(*args, **kwargs):
            if not old[0].exists():
                raise OSError("registry publication failed after deletion")
            return real_replace(*args, **kwargs)

        with mock.patch.object(self.module.os, "replace", side_effect=fail_after_delete):
            result = self.promote(new)
        self.assertEqual("promoted", result["status"])
        self.assertFalse(old[0].exists())
        self.registry = self.module.DeploymentArtifactRegistry(self.registry_path)
        result = self.promote(new)
        self.assertEqual("promoted", result["status"])
        self.assertFalse(result["deferred"])
        state = json.loads((self.registry_path / "registry.json").read_text())
        self.assertNotIn("inventory", state["bundles"][str(old[0])])
        self.verify(new[0])

    def test_partial_prune_never_accepts_new_foreign_entries_on_retry(self):
        old, new = self.established()
        real_unlink = self.module.os.unlink

        def fail_payload(path, *args, **kwargs):
            if path == "protected-catalog.sqlite3":
                raise OSError("injected partial prune")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(self.module.os, "unlink", side_effect=fail_payload):
            self.promote(new)
        foreign = old[0] / "foreign"
        foreign.write_bytes(b"not registered")
        self.registry = self.module.DeploymentArtifactRegistry(self.registry_path)
        result = self.promote(new)
        self.assertTrue(result["deferred"])
        self.assertEqual(b"not registered", foreign.read_bytes())
        self.assertTrue((old[0] / "protected-catalog.sqlite3").exists())

    def test_active_registry_lease_refuses_concurrent_promotion(self):
        old, new = self.established()
        with self.registry.lease(old[0]):
            result = self.promote(new)
        self.assertEqual("refused", result["status"])
        self.assertTrue(old[0].is_dir())
        self.assertTrue(new[0].is_dir())

    def test_symlink_or_hardlinked_bundle_content_is_never_registered(self):
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                bundle = self.bundle(kind)
                target = self.root / (kind + "-live-catalog")
                target.write_bytes(b"authoritative state")
                link = bundle[0] / "linked-catalog"
                if kind == "symlink":
                    link.symlink_to(target)
                else:
                    os.link(target, link)
                with self.assertRaises(self.module.RetentionError):
                    self.register(bundle)
                self.assertEqual(b"authoritative state", target.read_bytes())

    def test_broad_roots_and_stage_directory_are_not_bundle_ownership(self):
        for path in (Path("/"), Path("/home"), Path("/var/lib/lto-archiver"), self.root):
            with self.subTest(path=path), self.assertRaises(self.module.RetentionError):
                self.registry.register_verified_bundle(path, "a" * 64, verify_bundle=lambda path: None)

    def test_registry_symlink_is_refused_without_touching_foreign_state(self):
        foreign = self.root / "foreign"
        foreign.mkdir()
        sentinel = foreign / "sentinel"
        sentinel.write_bytes(b"keep")
        redirected = self.root / "redirected-registry"
        redirected.symlink_to(foreign, target_is_directory=True)
        with self.assertRaises(self.module.RetentionError):
            registry = self.module.DeploymentArtifactRegistry(redirected)
            registry.register_verified_bundle(*self.bundle("redirected"), verify_bundle=self.verify)
        self.assertEqual(b"keep", sentinel.read_bytes())


if __name__ == "__main__":
    unittest.main()
