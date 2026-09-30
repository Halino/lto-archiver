from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.test_rhel9_rollback import _load_module

GIB = 1024**3


class DeploymentStorageCapacityTests(unittest.TestCase):
    def setUp(self):
        self.module = _load_module()
        self.host = self.module.SystemRollbackHost()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.live = self.root / "live"
        self.bundle = self.root / "bundle"
        self.scratch = self.root / "scratch"
        for path in (self.live, self.bundle, self.scratch):
            path.mkdir()
        self.catalog = self.live / "application/catalog.db"
        self.catalog.parent.mkdir()
        with self.catalog.open("wb") as stream:
            stream.truncate(2 * GIB)
        self.backups = self.catalog.parent / "backups"
        self.backups.mkdir()
        self.roots = {
            identity: self.live / identity for identity in self.module.REQUIRED_SNAPSHOTS
        }
        self.roots["application_state"] = self.catalog.parent
        self.roots["systemd_dropins"].mkdir()
        self.sources = tuple(
            self.module.SnapshotSource(identity, 3 * GIB if identity == "application_state" else 0)
            for identity in self.module.REQUIRED_SNAPSHOTS
        )
        self.rpms = (SimpleNamespace(size=GIB),)
        self.recovery = self.live / "recovery"
        self.recovery.mkdir()
        self.protected = self.bundle / "protected-source/catalog.sqlite3"
        self.protected.parent.mkdir()
        with self.protected.open("wb") as stream:
            stream.truncate(2 * GIB)

    def check(self, *, shared=False, bundle_scratch_shared=False, free=None, compacted=None,
              restore=False, topology=None, manifest=None, proof=None):
        free = free or {"live": 15 * GIB, "bundle": 18 * GIB, "scratch": 12 * GIB}
        real_stat = os.stat

        def filesystem_stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            group = Path(path).relative_to(self.root).parts[0]
            values = list(result)
            devices = {"live": 1, "bundle": 2, "scratch": 2 if bundle_scratch_shared else 3}
            values[2] = 1 if shared else devices[group]
            if topology and Path(path) in topology:
                values[2] = topology[Path(path)]
            return os.stat_result(values)

        def available(path):
            return free["shared"] if shared else free[Path(path).relative_to(self.root).parts[0]]

        with (
            mock.patch.dict(self.module._SNAPSHOT_ROOTS, self.roots, clear=True),
            mock.patch.object(self.module, "_LIVE_CATALOG", self.catalog),
            mock.patch.object(self.module, "_PROTECTED_BACKUP_ROOT", self.backups),
            mock.patch.object(self.module, "_ROLLBACK_RECOVERY_ROOT", self.recovery, create=True),
            mock.patch.object(self.module.tempfile, "gettempdir", return_value=str(self.scratch)),
            mock.patch.object(self.module.os, "stat", side_effect=filesystem_stat),
            mock.patch.object(self.host, "available_bytes", side_effect=available),
        ):
            if restore:
                if manifest is None:
                    manifest = self.restore_manifest()
                self.host.verify_restore_capacity(self.bundle, manifest)
            elif compacted is None:
                self.host.verify_deployment_capacity(self.bundle, self.sources, self.rpms,
                                                      prove_absent_web_unit=proof)
            else:
                self.host.verify_compacted_deployment_capacity(
                    self.bundle, self.sources, self.rpms,
                    original_bytes=compacted[0], candidate_bytes=compacted[1],
                )

    def restore_manifest(self):
        files = [SimpleNamespace(relative_path="catalog.db", size=2 * GIB)]
        for path in self.backups.iterdir():
            files.append(SimpleNamespace(
                relative_path="backups/" + path.name, size=path.stat().st_size,
            ))
        return SimpleNamespace(
            schema=4,
            protected_backup_relative_path="protected-source/catalog.sqlite3",
            snapshots=tuple(SimpleNamespace(
                identity=row.identity, logical_bytes=row.logical_bytes,
                files=tuple(files) if row.identity == "application_state" else (),
            ) for row in self.sources),
        )

    def web_absence_proof(self, path):
        # Identity/ownership authentication is tested with the real fence in
        # retained workflow tests. This fixture isolates arithmetic/topology.
        if path != self.roots["custom_web_unit"] or not path.is_symlink():
            raise RuntimeError("projected path differs")

    def test_projected_owned_web_absence_keeps_capacity_reserves_and_mask(self):
        mask = self.roots["custom_web_unit"]
        mask.symlink_to("/dev/null")
        before = mask.lstat()
        self.check(proof=self.web_absence_proof)
        self.assertEqual(before, mask.lstat())
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(proof=self.web_absence_proof,
                       free={"live": 15 * GIB - 1, "bundle": 100 * GIB, "scratch": 100 * GIB})
        self.assertEqual(before, mask.lstat())

    def test_ordinary_deploy_and_restore_still_reject_web_symlink(self):
        self.roots["custom_web_unit"].symlink_to("/dev/null")
        for restore in (False, True):
            with self.subTest(restore=restore), self.assertRaisesRegex(self.module.RollbackError, "topology"):
                self.check(restore=restore)

    def test_projection_never_exempts_other_roots_or_destination_filesystems(self):
        self.roots["custom_web_unit"].symlink_to("/dev/null")
        config = self.roots["configuration"]
        config.symlink_to("/dev/null")
        with self.assertRaisesRegex(self.module.RollbackError, "topology"):
            self.check(proof=self.web_absence_proof)
        config.unlink()
        for path in (self.roots["custom_web_unit"].parent, self.catalog.parent, self.recovery):
            with self.subTest(path=path), self.assertRaisesRegex(self.module.RollbackError, "topology"):
                self.check(proof=self.web_absence_proof, topology={path: 9})

    def test_projection_requires_successful_proof_and_zero_snapshot(self):
        self.roots["custom_web_unit"].symlink_to("/dev/null")
        for proof in (True, lambda path: False, lambda path: True):
            with self.subTest(proof=proof), self.assertRaisesRegex(self.module.RollbackError, "proof"):
                self.check(proof=proof)
        self.sources = tuple(self.module.SnapshotSource(row.identity,
            1 if row.identity == "custom_web_unit" else row.logical_bytes) for row in self.sources)
        with self.assertRaisesRegex(self.module.RollbackError, "empty snapshot"):
            self.check(proof=self.web_absence_proof)

    def test_projection_is_revalidated_after_capacity_observation(self):
        mask = self.roots["custom_web_unit"]
        mask.symlink_to("/dev/null")
        real = self.host._verify_capacity_demands
        def changed(demands):
            real(demands)
            mask.unlink()
        with mock.patch.object(self.host, "_verify_capacity_demands", side_effect=changed), \
             self.assertRaisesRegex(RuntimeError, "projected path"):
            self.check(proof=self.web_absence_proof)

    def test_restore_uses_only_remaining_live_and_scratch_space_not_allocated_bundle(self):
        # Bundle and prepared backup already occupy disk. Only live3+2 and scratch2 remain.
        free = {"live": 15 * GIB, "bundle": 0, "scratch": 12 * GIB}
        self.check(restore=True, free=free)
        for filesystem in ("live", "scratch"):
            with self.subTest(filesystem=filesystem), self.assertRaisesRegex(self.module.RollbackError, "capacity"):
                self.check(restore=True, free=dict(free, **{filesystem: free[filesystem] - 1}))

    def test_restore_shared_filesystem_sums_only_future_allocations(self):
        # 3 snapshot + 2 protected restore + 2 scratch + 10 reserve, not initial25.
        self.check(restore=True, shared=True, free={"shared": 17 * GIB})
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(restore=True, shared=True, free={"shared": 17 * GIB - 1})

    def test_restore_uses_bundle_catalog_bound_not_changed_live_catalog(self):
        with self.catalog.open("wb") as stream:
            stream.truncate(100 * GIB)
        # Current failed state stays allocated; do not charge another copy or reclaim it.
        self.check(restore=True, free={"live": 15 * GIB, "bundle": 0, "scratch": 12 * GIB})

    def test_restore_protected_backup_scratch_is_derived_from_snapshot_evidence(self):
        manifest = self.restore_manifest()
        application = next(row for row in manifest.snapshots if row.identity == "application_state")
        application.logical_bytes = 5 * GIB
        application.files += (SimpleNamespace(
            relative_path="backups/catalog/20260912T220000000000Z-abcdef123456-p-v40-0123456789abcdef.sqlite3",
            size=3 * GIB,
        ),)
        # The backup need not exist in current failed live state: it will be restored.
        self.check(restore=True, manifest=manifest,
                   free={"live": 17 * GIB, "bundle": 0, "scratch": 16 * GIB})
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(restore=True, manifest=manifest,
                       free={"live": 17 * GIB, "bundle": 0, "scratch": 16 * GIB - 1})

    def test_restore_catalog_wal_snapshot_bound_can_exceed_protected_backup(self):
        manifest = self.restore_manifest()
        application = next(row for row in manifest.snapshots if row.identity == "application_state")
        application.files += (SimpleNamespace(relative_path="catalog.db-wal", size=GIB),)
        self.check(restore=True, manifest=manifest,
                   free={"live": 15 * GIB, "bundle": 0, "scratch": 13 * GIB})
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(restore=True, manifest=manifest,
                       free={"live": 15 * GIB, "bundle": 0, "scratch": 13 * GIB - 1})

    def test_restore_large_shared_peak_preserves_twenty_percent_reserve(self):
        manifest = self.restore_manifest()
        application = next(row for row in manifest.snapshots if row.identity == "application_state")
        application.logical_bytes = 100 * GIB
        application.files[0].size = 100 * GIB
        with self.protected.open("wb") as stream:
            stream.truncate(100 * GIB)
        # Future data300 + reserve60, with all existing files still allocated.
        self.check(restore=True, manifest=manifest, shared=True, free={"shared": 360 * GIB})
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(restore=True, manifest=manifest, shared=True, free={"shared": 360 * GIB - 1})

    def test_restore_rejects_cross_filesystem_recovery_before_copying(self):
        for restore in (False, True):
            with self.subTest(restore=restore), self.assertRaisesRegex(self.module.RollbackError, "filesystem|topology"):
                self.check(restore=restore, topology={self.recovery: 9},
                           free={"live": 100 * GIB, "bundle": 100 * GIB, "scratch": 100 * GIB})

    def test_restore_rejects_snapshot_root_or_nested_cross_filesystem_mount(self):
        nested = self.catalog.parent / "mounted-backups"
        nested.mkdir()
        for mount in (self.catalog.parent, nested):
            for restore in (False, True):
                with self.subTest(mount=mount, restore=restore), self.assertRaisesRegex(self.module.RollbackError, "filesystem|topology"):
                    self.check(restore=restore, topology={mount: 9},
                               free={"live": 100 * GIB, "bundle": 100 * GIB, "scratch": 100 * GIB})

    def test_restore_rejects_invalid_snapshot_closure_and_sizes(self):
        manifest = self.restore_manifest()
        manifest.snapshots = manifest.snapshots[1:]
        with self.assertRaises(self.module.RollbackError):
            self.check(restore=True, manifest=manifest)
        for size in (-1, True, 1.0, "1", None):
            manifest = self.restore_manifest()
            manifest.snapshots[0].logical_bytes = size
            with self.subTest(size=size), self.assertRaises(self.module.RollbackError):
                self.check(restore=True, manifest=manifest)

    def test_separate_filesystems_accept_exact_peak_with_each_reserve(self):
        # Bundle: 3 snapshot + 1 RPM + 2*2 protected copies + 10 reserve.
        # Live: 3 restored snapshot + 2 temporary catalog + 10 reserve.
        # Scratch: largest validation 2 + 10 reserve.
        self.check()

    def test_root_restore_space_is_required_even_with_plenty_of_bundle_space(self):
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(free={"live": 15 * GIB - 1, "bundle": 100 * GIB, "scratch": 100 * GIB})

    def test_scratch_space_is_checked_independently(self):
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(free={"live": 100 * GIB, "bundle": 100 * GIB, "scratch": 12 * GIB - 1})

    def test_bundle_keeps_both_prepared_and_bundled_protected_catalogs(self):
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(free={"live": 100 * GIB, "bundle": 18 * GIB - 1, "scratch": 100 * GIB})

    def test_wal_contributes_to_the_coherent_backup_size_bound(self):
        with self.catalog.with_name("catalog.db-wal").open("wb") as stream:
            stream.truncate(GIB)
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(free={"live": 16 * GIB, "bundle": 20 * GIB, "scratch": 13 * GIB - 1})
        self.check(free={"live": 16 * GIB, "bundle": 20 * GIB, "scratch": 13 * GIB})

    def test_shared_filesystem_sums_demands_before_applying_one_reserve(self):
        # Data peak is 8 bundle + 5 live + 2 scratch = 15 GiB.
        self.check(shared=True, free={"shared": 25 * GIB})
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(shared=True, free={"shared": 25 * GIB - 1})

    def test_bundle_and_scratch_share_space_while_live_is_separate(self):
        self.check(bundle_scratch_shared=True, free={"live": 15 * GIB, "bundle": 20 * GIB, "scratch": 20 * GIB})
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(bundle_scratch_shared=True, free={"live": 15 * GIB, "bundle": 20 * GIB - 1, "scratch": 20 * GIB - 1})

    def test_service_protected_backup_requires_two_simultaneous_scratch_copies(self):
        backup = self.backups / "20260912T220000000000Z-abcdef123456-p-v40-0123456789abcdef.sqlite3"
        with backup.open("wb") as stream:
            stream.truncate(3 * GIB)
        # Snapshot now includes catalog2 + protected backup3.
        self.sources = tuple(
            self.module.SnapshotSource(row.identity, 5 * GIB if row.identity == "application_state" else 0)
            for row in self.sources
        )
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(free={"live": 100 * GIB, "bundle": 100 * GIB, "scratch": 16 * GIB - 1})
        self.check(free={"live": 100 * GIB, "bundle": 100 * GIB, "scratch": 16 * GIB})

    def test_large_shared_peak_keeps_twenty_percent_not_only_ten_gib(self):
        with self.catalog.open("wb") as stream:
            stream.truncate(100 * GIB)
        self.sources = tuple(
            self.module.SnapshotSource(row.identity, 100 * GIB if row.identity == "application_state" else 0)
            for row in self.sources
        )
        # Data peak 601 GiB needs about 120.2 GiB reserve, not only 10 GiB.
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(shared=True, free={"shared": 650 * GIB})
        self.check(shared=True, free={"shared": 730 * GIB})

    def test_compacted_projection_replaces_catalog_once_and_keeps_input_rows(self):
        original_sources = self.sources
        # App snapshot: 3 - 2 + 1 = 2 GiB. Bundle: 2 + 1 RPM + 2 protected = 5.
        # Live: 2 restored + 1 protected restore + 1 future installed copy = 4.
        # Scratch: 1. Each separate filesystem keeps another 10 GiB free.
        free = {"live": 14 * GIB, "bundle": 15 * GIB, "scratch": 11 * GIB}
        self.check(compacted=(2 * GIB, GIB), free=free)
        self.assertEqual(original_sources, self.sources)
        self.assertEqual(3 * GIB, next(
            row.logical_bytes for row in self.sources if row.identity == "application_state"
        ))
        # The normal path still measures the original live catalog, not B.
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(free=free)
        self.check()

    def test_compacted_candidate_on_home_still_budgets_installation_and_restore_on_live(self):
        candidate = self.bundle / "catalog-candidate.db"
        with candidate.open("wb") as stream:
            stream.truncate(GIB)
        free = {"live": 14 * GIB - 1, "bundle": 100 * GIB, "scratch": 100 * GIB}
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(compacted=(2 * GIB, candidate.stat().st_size), free=free)
        free["live"] += 1
        self.check(compacted=(2 * GIB, candidate.stat().st_size), free=free)

    def test_compacted_projection_preserves_service_backup_in_snapshot_and_double_scratch(self):
        backup = self.backups / "20260912T220000000000Z-abcdef123456-p-v40-0123456789abcdef.sqlite3"
        with backup.open("wb") as stream:
            stream.truncate(3 * GIB)
        self.sources = tuple(
            self.module.SnapshotSource(row.identity, 5 * GIB if row.identity == "application_state" else 0)
            for row in self.sources
        )
        # App remains 1 candidate + 3 retained backup. Bundle=7, live=6, scratch=6.
        free = {"live": 16 * GIB, "bundle": 17 * GIB, "scratch": 16 * GIB}
        self.check(compacted=(2 * GIB, GIB), free=free)
        for filesystem, available in free.items():
            with self.subTest(filesystem=filesystem), self.assertRaisesRegex(self.module.RollbackError, "capacity"):
                self.check(compacted=(2 * GIB, GIB), free=dict(free, **{filesystem: available - 1}))
        self.assertEqual(3 * GIB, backup.stat().st_size)

    def test_compacted_projection_keeps_other_snapshot_and_sqlite_scratch_demands(self):
        self.sources = tuple(
            self.module.SnapshotSource(row.identity, 4 * GIB if row.identity == "command_broker_state" else row.logical_bytes)
            for row in self.sources
        )
        # Existing app extra1 + candidate1 + broker4 = 6 GiB of snapshots.
        free = {"live": 18 * GIB, "bundle": 19 * GIB, "scratch": 14 * GIB}
        self.check(compacted=(2 * GIB, GIB), free=free)
        for filesystem, available in free.items():
            with self.subTest(filesystem=filesystem), self.assertRaisesRegex(self.module.RollbackError, "capacity"):
                self.check(compacted=(2 * GIB, GIB), free=dict(free, **{filesystem: available - 1}))

    def test_compacted_sparse_original_never_credits_reclaimable_bytes(self):
        with self.catalog.open("wb") as stream:
            stream.truncate(100 * GIB)
        self.assertLess(self.catalog.stat().st_blocks * 512, self.catalog.stat().st_size)
        self.sources = tuple(
            self.module.SnapshotSource(row.identity, 101 * GIB if row.identity == "application_state" else 0)
            for row in self.sources
        )
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(compacted=(100 * GIB, GIB), free={
                "live": 14 * GIB - 1, "bundle": 100 * GIB, "scratch": 100 * GIB,
            })
        self.check(compacted=(100 * GIB, GIB), free={
            "live": 14 * GIB, "bundle": 15 * GIB, "scratch": 11 * GIB,
        })

    def test_compacted_shared_filesystem_includes_future_installed_copy_once(self):
        # Bundle5 + live4 + scratch1 + reserve10 = 20 GiB.
        self.check(compacted=(2 * GIB, GIB), shared=True, free={"shared": 20 * GIB})
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(compacted=(2 * GIB, GIB), shared=True, free={"shared": 20 * GIB - 1})

    def test_compacted_bundle_and_scratch_can_share_without_moving_live_demands(self):
        free = {"live": 14 * GIB, "bundle": 16 * GIB, "scratch": 16 * GIB}
        self.check(compacted=(2 * GIB, GIB), bundle_scratch_shared=True, free=free)
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(compacted=(2 * GIB, GIB), bundle_scratch_shared=True, free={
                "live": 100 * GIB, "bundle": 16 * GIB - 1, "scratch": 16 * GIB - 1,
            })

    def test_compacted_large_shared_peak_preserves_twenty_percent_reserve(self):
        with self.catalog.open("wb") as stream:
            stream.truncate(100 * GIB)
        self.sources = tuple(
            self.module.SnapshotSource(row.identity, 101 * GIB if row.identity == "application_state" else 0)
            for row in self.sources
        )
        # Projected snapshots11 + bundle protected20 + RPM1 + restore snapshots11
        # + protected restore10 + installed copy10 + scratch10 = 73 GiB.
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.check(compacted=(100 * GIB, 10 * GIB), shared=True, free={"shared": 84 * GIB})
        self.check(compacted=(100 * GIB, 10 * GIB), shared=True, free={"shared": 90 * GIB})

    def test_compacted_projection_requires_positive_integer_catalog_sizes(self):
        for value in (0, -1, True, 1.0, "1", None):
            for compacted in ((value, GIB), (2 * GIB, value)):
                with self.subTest(compacted=compacted), self.assertRaises(self.module.RollbackError):
                    self.check(compacted=compacted)

    def test_compacted_projection_refuses_original_larger_than_application_snapshot(self):
        with self.assertRaises(self.module.RollbackError):
            self.check(compacted=(4 * GIB, GIB))

    def test_compacted_projection_requires_exact_snapshot_closure(self):
        original_sources = self.sources
        for invalid in (original_sources[1:], tuple(reversed(original_sources)), original_sources + original_sources[:1]):
            self.sources = invalid
            with self.subTest(identities=tuple(row.identity for row in invalid)), self.assertRaises(self.module.RollbackError):
                self.check(compacted=(2 * GIB, GIB))

    def test_compacted_projection_refuses_invalid_snapshot_and_rpm_sizes(self):
        original_sources = self.sources
        for value in (-1, True, 1.0, "1", None):
            self.sources = tuple(
                self.module.SnapshotSource(row.identity, value if row.identity == "configuration" else row.logical_bytes)
                for row in original_sources
            )
            with self.subTest(snapshot_size=value), self.assertRaises(self.module.RollbackError):
                self.check(compacted=(2 * GIB, GIB))
        self.sources = original_sources
        for value in (-1, True, 1.0, "1", None):
            self.rpms = (SimpleNamespace(size=value),)
            with self.subTest(rpm_size=value), self.assertRaises(self.module.RollbackError):
                self.check(compacted=(2 * GIB, GIB))
