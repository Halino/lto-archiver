from __future__ import annotations

import builtins
import os
import tempfile
import unittest
from concurrent.futures import Executor, Future
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import ltobackup.application as application_module
import ltobackup.automation as automation_module
import ltobackup.catalog as catalog_module
import ltobackup.daemon.archive_runner as archive_runner_module
import ltobackup.engine as engine_module
import ltobackup.scanner as scanner_module
from ltobackup.application import LtoApplication
from ltobackup.broker.client import UnixBrokeredCgroupScopeApi
from ltobackup.catalog import Catalog
from ltobackup.daemon.api_models import CreateCatalogRestorePlanRequestV1
from ltobackup.daemon.archive_runtime import BrokeredLtfsInfoMediaIdentityProbe
from ltobackup.daemon.backups import BackupManager
from ltobackup.daemon.events import EventBus
from ltobackup.daemon.operations import OperationManager
from ltobackup.daemon.service import (
    CatalogRestorePlanConflict,
    DaemonService,
    Principal,
)
from ltobackup.engine import BackupEngine
from ltobackup.linux_settings import LinuxPaths, LinuxSettings
from ltobackup.managed_sources import ManagedSourceVerifier
from ltobackup.share_broker.client import ShareBrokerClient
from ltobackup.tape.command_supervisor import TrackedCommandSupervisor
from ltobackup.tape.linux_ltfs import LinuxLtfsBackend

PATH_FIXTURE = (
    ("Caffè/episodio.mkv", "Caffè/episodio.mkv"),
    ("I Flintstones /episode.mkv", "~lto1~I Flintstones%20/episode.mkv"),
    ("I Flintstones%20/episode.mkv", "I Flintstones%20/episode.mkv"),
    ("~lto1~literal/file.mkv", "~lto1~~lto1~literal/file.mkv"),
    ("CON.txt", "~lto1~CON.txt"),
)


class _HoldingExecutor(Executor):
    def __init__(self) -> None:
        self.submissions = 0

    def submit(self, fn, /, *args, **kwargs):
        self.submissions += 1
        future: Future[None] = Future()
        return future


class _ForbiddenCall:
    def __init__(self, name: str) -> None:
        self.name = name
        self.calls = 0

    def __call__(self, *_args, **_kwargs):
        self.calls += 1
        raise AssertionError(f"forbidden catalog I/O category called: {self.name}")


class _ForbiddenDependency:
    def __init__(self, call: _ForbiddenCall) -> None:
        self._call = call

    def __getattr__(self, _name: str):
        return self._call


class OfflineCatalogSearchAcceptanceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addAsyncCleanup(self._cleanup)
        self.root = Path(self.temporary.name)
        self.source_a = self.root / "source-a"
        self.source_b = self.root / "source-b"
        self.source_a.mkdir()
        self.source_b.mkdir()
        self.mount = self.root / "never-mounted"
        self.mount.mkdir()
        self.restore_root = self.root / "restore"
        self.restore_root.mkdir()
        self.settings = LinuxSettings(
            state_dir=self.root / "state",
            socket_path=self.root / "run" / "daemon.sock",
            source_roots=(self.source_a, self.source_b),
            restore_roots=(self.restore_root,),
            mount_path=self.mount,
        )
        self.paths = LinuxPaths.from_settings(self.settings)
        self.backups = BackupManager(self.paths.catalog_file, self.paths.backup_dir)
        self.backups.prepare_and_initialize()
        self._seed_catalog()
        with Catalog(self.paths.catalog_file) as catalog:
            fence = catalog.claim_daemon_owner("task-6-catalog")
        self.executor = _HoldingExecutor()
        self.operations = OperationManager(
            lambda: Catalog(self.paths.catalog_file), fence, executor=self.executor
        )
        self.events = EventBus(lambda: Catalog(self.paths.catalog_file))
        self.service = DaemonService(
            self.paths,
            self.settings,
            self.backups,
            self.operations,
            self.events,
            share_executor=self.executor,
        )
        self.service.startup()
        self.addAsyncCleanup(self.service.shutdown)
        self.source_a.rmdir()
        self.source_b.rmdir()
        self.mount.rmdir()
        self.principal = Principal("task-6-reader", role="operator")
        self.spies = {
            name: _ForbiddenCall(name)
            for name in (
                "application.analyze",
                "scanner.analyze",
                "scanner.scan",
                "engine.scan",
                "application.plan",
                "application.select",
                "engine.plan",
                "engine.select",
                "application.mapper",
                "catalog.mapper",
                "engine.mapper",
                "archive.mapper",
                "source.scandir",
                "source.walk",
                "source.iterdir",
                "source.open",
                "source.read_text",
                "source.read_bytes",
                "source.stat",
                "source.lstat",
                "source.glob",
                "source.rglob",
                "source.copy",
                "source.hash",
                "broker.exchange",
                "command.run",
                "share.exchange",
                "drive_lock",
                "broker.dependency",
                "share.dependency",
                "ltfs.wait",
                "ltfs.preformat_wait",
                "ltfs.format",
                "ltfs.mount",
                "ltfs.unmount",
                "ltfs.eject",
                "ltfs.recover",
                "media.identify",
                "media.identify_preformat",
                "media.identify_unmounted",
                "media.identify_mounted",
                "volume.automation",
                "volume.engine",
                "managed.verify",
                "managed.admit",
                "managed.release",
                "share.start",
                "share.execute",
                "operation.start",
                "operation.retry",
                "executor.submit",
                "background.create_task",
            )
        }

    async def _cleanup(self) -> None:
        self.temporary.cleanup()

    def _seed_catalog(self) -> None:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.add_library("LIB-A", "Library A", str(self.source_a))
            catalog.add_library("LIB-B", "Library B", str(self.source_b))
            tapes = (
                ("TAPE-A", "SERIAL-A", "VOLUME-A", "CASSETTE-A"),
                ("TAPE-B", "SERIAL-B", "VOLUME-B", "CASSETTE-B"),
                ("TAPE-C", "SERIAL-C", "VOLUME-C", "CASSETTE-C"),
            )
            for tape_id, serial, volume, cassette in tapes:
                catalog.register_tape(
                    tape_id, serial, volume, "LTFS", str(self.mount), cassette
                )
            catalog.create_automatic_job(
                "JOB-A",
                "LIB-A",
                "/dev/never-opened",
                str(self.mount),
                [("AB1234", "SERIAL-A", 1, 101), ("AB1235", "SERIAL-B", 5, 515)],
            )
            catalog.create_automatic_job(
                "JOB-B",
                "LIB-B",
                "/dev/never-opened",
                str(self.mount),
                [("CD5678", "SERIAL-C", 1, 303)],
            )
            catalog.create_block(
                "BLOCK-OLD", "LIB-A", "TAPE-A", "libraries/LIB-A/blocks/BLOCK-OLD", 1, 101
            )
            self.old_version = catalog.record_file_version(
                "LIB-A",
                "BLOCK-OLD",
                "TAPE-A",
                PATH_FIXTURE[0][0],
                PATH_FIXTURE[0][1],
                101,
                101,
                "a" * 64,
            )
            catalog.complete_block("BLOCK-OLD")
            catalog.create_block(
                "BLOCK-NEW", "LIB-A", "TAPE-B", "libraries/LIB-A/blocks/BLOCK-NEW", 5, 515
            )
            self.current_version = None
            self.path_versions: dict[str, int] = {}
            for index, (logical, physical) in enumerate(PATH_FIXTURE, 1):
                version_id = catalog.record_file_version(
                    "LIB-A",
                    "BLOCK-NEW",
                    "TAPE-B",
                    logical,
                    physical,
                    200 + index,
                    200 + index,
                    f"{index + 10:064x}",
                )
                self.path_versions[logical] = version_id
                if logical == PATH_FIXTURE[0][0]:
                    self.current_version = version_id
            catalog.complete_block("BLOCK-NEW")
            catalog.create_block(
                "BLOCK-OTHER", "LIB-B", "TAPE-C", "libraries/LIB-B/blocks/BLOCK-OTHER", 1, 303
            )
            self.other_version = catalog.record_file_version(
                "LIB-B",
                "BLOCK-OTHER",
                "TAPE-C",
                "other/feature.mov",
                "other/feature.mov",
                303,
                303,
                "f" * 64,
            )
            catalog.complete_block("BLOCK-OTHER")
            for version_id, copied_at in (
                (self.old_version, "2026-08-27T10:00:00+00:00"),
                (self.current_version, "2026-08-28T10:00:00+00:00"),
                (self.other_version, "2026-08-28T11:00:00+00:00"),
            ):
                catalog.connection.execute(
                    "UPDATE file_versions SET copied_at=? WHERE id=?",
                    (copied_at, version_id),
                )
            catalog.update_automatic_cassette(
                "JOB-A", 1, "completed", tape_id="TAPE-A", block_id="BLOCK-OLD"
            )
            catalog.update_automatic_cassette(
                "JOB-A", 2, "completed", tape_id="TAPE-B", block_id="BLOCK-NEW"
            )
            catalog.update_automatic_cassette(
                "JOB-B", 1, "completed", tape_id="TAPE-C", block_id="BLOCK-OTHER"
            )
            catalog.connection.execute(
                "UPDATE automatic_jobs SET status='completed', completed_at=? "
                "WHERE id IN ('JOB-A','JOB-B')",
                ("2026-08-28T12:00:00+00:00",),
            )
            catalog.connection.commit()
        assert self.current_version is not None

    def _catalog_dump(self) -> tuple[str, ...]:
        with Catalog(self.paths.catalog_file) as catalog:
            return tuple(catalog.connection.iterdump())

    def _table_snapshot(self) -> dict[str, tuple[tuple[object, ...], ...]]:
        with Catalog(self.paths.catalog_file) as catalog:
            tables = tuple(
                row[0]
                for row in catalog.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            )
            return {
                table: tuple(tuple(row) for row in catalog.connection.execute(f'SELECT * FROM "{table}"'))
                for table in tables
            }

    def _assert_paths_absent(self) -> None:
        self.assertFalse(self.source_a.exists())
        self.assertFalse(self.source_b.exists())
        self.assertFalse(self.mount.exists())

    def _guarded_path(self, value: object) -> bool:
        try:
            candidate = Path(os.fsdecode(os.fspath(value)))
        except (TypeError, ValueError):
            return False
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        roots = (self.source_a, self.source_b, self.mount, self.restore_root)
        return any(candidate == root or root in candidate.parents for root in roots)

    def _path_guard(self, name: str, original):
        forbidden = self.spies[name]

        def guarded(path, *args, **kwargs):
            if self._guarded_path(path):
                return forbidden(path, *args, **kwargs)
            return original(path, *args, **kwargs)

        return guarded

    def _io_guard(self) -> ExitStack:
        stack = ExitStack()
        stack.enter_context(
            patch.object(LtoApplication, "analyze_library", self.spies["application.analyze"])
        )
        stack.enter_context(
            patch.object(application_module, "analyze_library", self.spies["application.analyze"])
        )
        stack.enter_context(
            patch.object(scanner_module, "analyze_library", self.spies["scanner.analyze"])
        )
        stack.enter_context(
            patch.object(scanner_module, "scan_library", self.spies["scanner.scan"])
        )
        stack.enter_context(patch.object(BackupEngine, "scan", self.spies["engine.scan"]))
        for module, name, key in (
            (application_module, "_plan_ltfs_batches", "application.plan"),
            (application_module, "_select_ltfs_batch", "application.select"),
            (engine_module, "plan_tape_batches", "engine.plan"),
            (engine_module, "select_tape_batch", "engine.select"),
            (application_module, "ltfs_tape_relative_path", "application.mapper"),
            (catalog_module, "ltfs_tape_relative_path", "catalog.mapper"),
            (engine_module, "ltfs_tape_relative_path", "engine.mapper"),
            (archive_runner_module, "ltfs_tape_relative_path", "archive.mapper"),
            (engine_module, "copy_and_hash", "source.copy"),
            (engine_module, "sha256_file", "source.hash"),
            (scanner_module, "sha256_file", "source.hash"),
            (automation_module, "inspect_volume", "volume.automation"),
            (engine_module, "inspect_volume", "volume.engine"),
        ):
            stack.enter_context(patch.object(module, name, self.spies[key]))
        for name, key in (
            ("open", "source.open"),
            ("read_text", "source.read_text"),
            ("read_bytes", "source.read_bytes"),
            ("stat", "source.stat"),
            ("lstat", "source.lstat"),
            ("glob", "source.glob"),
            ("rglob", "source.rglob"),
            ("iterdir", "source.iterdir"),
        ):
            original = getattr(Path, name)
            stack.enter_context(
                patch.object(Path, name, self._path_guard(key, original))
            )
        stack.enter_context(
            patch.object(
                builtins,
                "open",
                self._path_guard("source.open", builtins.open),
            )
        )
        stack.enter_context(
            patch.object(os, "scandir", self._path_guard("source.scandir", os.scandir))
        )
        stack.enter_context(
            patch.object(os, "walk", self._path_guard("source.walk", os.walk))
        )
        for owner, name, key in (
            (UnixBrokeredCgroupScopeApi, "_exchange", "broker.exchange"),
            (TrackedCommandSupervisor, "run", "command.run"),
            (ShareBrokerClient, "_exchange", "share.exchange"),
            (LinuxLtfsBackend, "wait_for_media", "ltfs.wait"),
            (LinuxLtfsBackend, "wait_for_preformat_media", "ltfs.preformat_wait"),
            (LinuxLtfsBackend, "format", "ltfs.format"),
            (LinuxLtfsBackend, "mount", "ltfs.mount"),
            (LinuxLtfsBackend, "unmount", "ltfs.unmount"),
            (LinuxLtfsBackend, "unload", "ltfs.eject"),
            (LinuxLtfsBackend, "recover_pending_ltfs_session", "ltfs.recover"),
            (LinuxLtfsBackend, "identify", "media.identify"),
            (LinuxLtfsBackend, "identify_preformat", "media.identify_preformat"),
            (
                BrokeredLtfsInfoMediaIdentityProbe,
                "identify_unmounted",
                "media.identify_unmounted",
            ),
            (
                BrokeredLtfsInfoMediaIdentityProbe,
                "identify_mounted",
                "media.identify_mounted",
            ),
            (ManagedSourceVerifier, "verify_library", "managed.verify"),
            (DaemonService, "admit_job_managed_sources", "managed.admit"),
            (DaemonService, "release_job_managed_sources", "managed.release"),
        ):
            stack.enter_context(patch.object(owner, name, self.spies[key]))
        management = self.service._management
        stack.enter_context(
            patch.object(
                management,
                "_drive_lock",
                _ForbiddenDependency(self.spies["drive_lock"]),
            )
        )
        stack.enter_context(
            patch.object(
                management,
                "_broker",
                _ForbiddenDependency(self.spies["broker.dependency"]),
            )
        )
        stack.enter_context(
            patch.object(
                management,
                "_share_broker",
                _ForbiddenDependency(self.spies["share.dependency"]),
            )
        )
        stack.enter_context(
            patch.object(
                management,
                "start_network_share_operation",
                self.spies["share.start"],
            )
        )
        stack.enter_context(
            patch.object(
                management,
                "_execute_network_share_operation",
                self.spies["share.execute"],
            )
        )
        stack.enter_context(
            patch.object(self.operations, "start", self.spies["operation.start"])
        )
        stack.enter_context(
            patch.object(
                self.operations,
                "retry_native_recovery",
                self.spies["operation.retry"],
            )
        )
        stack.enter_context(
            patch.object(self.executor, "submit", self.spies["executor.submit"])
        )
        stack.enter_context(
            patch(
                "ltobackup.daemon.api.asyncio.create_task",
                self.spies["background.create_task"],
            )
        )
        return stack

    def _assert_zero_io(self) -> None:
        self.assertEqual(
            {name: 0 for name in self.spies},
            {name: spy.calls for name, spy in self.spies.items()},
        )
        self.assertEqual(0, self.executor.submissions)
        self._assert_paths_absent()

    def _read_without_catalog_mutation(self, callback):
        self._assert_paths_absent()
        before = self._catalog_dump()
        with self._io_guard():
            result = callback()
        self.assertEqual(before, self._catalog_dump())
        self._assert_zero_io()
        return result

    def test_filename_search_and_library_browse_work_with_all_paths_absent_and_zero_io(self) -> None:
        page = self._read_without_catalog_mutation(
            lambda: self.service.search_catalog_file_versions(
                self.principal, query="episodio", include_history=True, limit=1
            )
        )
        second = self._read_without_catalog_mutation(
            lambda: self.service.search_catalog_file_versions(
                self.principal,
                query="episodio",
                include_history=True,
                limit=1,
                cursor=page.next_cursor,
            )
        )
        versions = page.items + second.items
        self.assertEqual(
            [self.current_version, self.old_version], [item.id for item in versions]
        )
        self.assertEqual([True, False], [item.is_current for item in versions])
        self.assertEqual(["AB1235", "AB1234"], [item.physical_label for item in versions])
        self.assertEqual(["BLOCK-NEW", "BLOCK-OLD"], [item.block_id for item in versions])
        self.assertEqual([PATH_FIXTURE[0][0]] * 2, [item.relative_path for item in versions])
        self.assertEqual([PATH_FIXTURE[0][1]] * 2, [item.tape_relative_path for item in versions])
        self.assertEqual([201, 101], [item.size for item in versions])
        self.assertEqual([f"{11:064x}", "a" * 64], [item.sha256 for item in versions])
        self.assertEqual(["JOB-A", "JOB-A"], [item.job_id for item in versions])
        self.assertEqual(["LIB-A", "LIB-A"], [item.library_id for item in versions])

        root = self._read_without_catalog_mutation(
            lambda: self.service.browse_catalog_backup_children(
                "LIB-A", "", self.principal
            )
        )
        self.assertIn("Caffè", [item.name for item in root.items])
        nested = self._read_without_catalog_mutation(
            lambda: self.service.browse_catalog_backup_children(
                "LIB-A", "Caffè", self.principal
            )
        )
        self.assertEqual([self.current_version], [item.id for item in nested.items])
        detail = self._read_without_catalog_mutation(
            lambda: self.service.get_catalog_file_version(self.current_version, self.principal)
        )
        self.assertEqual(PATH_FIXTURE[0][0], detail.relative_path)
        self.assertEqual(PATH_FIXTURE[0][1], detail.tape_relative_path)
        self.assertNotIn(detail.physical_label or "", detail.tape_relative_path)

    def test_job_and_cassette_filtered_views_resolve_the_same_offline_version_identities(self) -> None:
        job_page = self._read_without_catalog_mutation(
            lambda: self.service.search_catalog_file_versions(
                self.principal, job_id="JOB-A", include_history=True
            )
        )
        cassette_page = self._read_without_catalog_mutation(
            lambda: self.service.search_catalog_file_versions(
                self.principal, cassette="AB1234", include_history=True
            )
        )
        library_page = self._read_without_catalog_mutation(
            lambda: self.service.search_catalog_file_versions(
                self.principal, library_id="LIB-B", include_history=True
            )
        )
        self.assertEqual(
            {self.old_version, *self.path_versions.values()},
            {item.id for item in job_page.items},
        )
        self.assertEqual({self.old_version}, {item.id for item in cassette_page.items})
        self.assertEqual({self.other_version}, {item.id for item in library_page.items})
        for item in job_page.items + cassette_page.items + library_page.items:
            detail = self._read_without_catalog_mutation(
                lambda version_id=item.id: self.service.get_catalog_file_version(
                    version_id, self.principal
                )
            )
            self.assertEqual(item, detail)

    async def test_offline_restore_plan_snapshots_catalog_mapping_without_source_tape_or_hardware_io(self) -> None:
        request = CreateCatalogRestorePlanRequestV1(
            file_version_ids=(self.current_version, self.old_version),
            destination_root=str(self.restore_root),
        )
        before = self._table_snapshot()
        self._assert_paths_absent()
        with self._io_guard():
            created = await self.service.create_catalog_restore_plan(
                request, "task-6-restore", self.principal
            )
        after = self._table_snapshot()
        changed = {table for table in before if before[table] != after[table]}
        self.assertEqual(
            {
                "audit_entries",
                "management_idempotency",
                "restore_plan_cassettes",
                "restore_plan_destinations",
                "restore_plan_items",
                "restore_plans",
            },
            changed,
        )
        self.assertEqual("exact", created.destination_state)
        self.assertIsNotNone(created.destination)
        assert created.destination is not None
        self.assertEqual(str(self.restore_root), created.destination.root)
        self.assertEqual(str(self.restore_root), created.destination.anchor)
        self.assertEqual(
            (self.current_version, self.old_version),
            tuple(item.file_version_id for item in created.items),
        )
        self.assertEqual(
            (PATH_FIXTURE[0][0], PATH_FIXTURE[0][0]),
            tuple(item.relative_path for item in created.items),
        )
        self.assertEqual(
            (PATH_FIXTURE[0][1], PATH_FIXTURE[0][1]),
            tuple(item.tape_relative_path for item in created.items),
        )
        self.assertEqual(("AB1235", "AB1234"), tuple(item.physical_label for item in created.items))
        self.assertEqual(("VOLUME-B", "VOLUME-A"), tuple(item.volume_label for item in created.items))
        self.assertEqual(("BLOCK-NEW", "BLOCK-OLD"), tuple(item.block_id for item in created.items))
        self.assertEqual((True, False), tuple(item.is_current for item in created.items))
        self._assert_zero_io()

        with self._io_guard():
            replay = await self.service.create_catalog_restore_plan(
                request, "task-6-restore", self.principal
            )
        self.assertEqual(created, replay)
        self.assertEqual(after, self._table_snapshot())
        self._assert_zero_io()
        changed_request = CreateCatalogRestorePlanRequestV1(
            file_version_ids=(self.old_version,),
            destination_root=str(self.restore_root),
        )
        with self._io_guard(), self.assertRaises(CatalogRestorePlanConflict):
            await self.service.create_catalog_restore_plan(
                changed_request, "task-6-restore", self.principal
            )
        self.assertEqual(after, self._table_snapshot())
        self._assert_zero_io()

    async def test_restore_snapshot_columns_migrate_additively_and_refresh_replay(self) -> None:
        request = CreateCatalogRestorePlanRequestV1(
            file_version_ids=(self.current_version,),
            destination_root=str(self.restore_root),
        )
        with self._io_guard():
            created = await self.service.create_catalog_restore_plan(
                request, "task-6-migration", self.principal
            )
        self.assertEqual((True,), tuple(item.is_current for item in created.items))
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.connection.executescript(
                """
                DROP TRIGGER restore_plan_items_immutable_update;
                DROP TRIGGER restore_plan_items_immutable_delete;
                ALTER TABLE restore_plan_items RENAME TO restore_plan_items_current;
                CREATE TABLE restore_plan_items (
                    plan_id TEXT NOT NULL REFERENCES restore_plans(id) ON DELETE RESTRICT,
                    sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 200),
                    file_version_id INTEGER NOT NULL,
                    library_id TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    tape_relative_path TEXT NOT NULL,
                    tape_id TEXT NOT NULL,
                    cassette_number TEXT NOT NULL,
                    physical_label TEXT,
                    size INTEGER NOT NULL CHECK(size>=0),
                    sha256 TEXT NOT NULL CHECK(length(sha256)=64),
                    copied_at TEXT NOT NULL,
                    PRIMARY KEY(plan_id,sequence),
                    UNIQUE(plan_id,file_version_id)
                );
                INSERT INTO restore_plan_items(
                    plan_id,sequence,file_version_id,library_id,relative_path,
                    tape_relative_path,tape_id,cassette_number,physical_label,
                    size,sha256,copied_at
                )
                SELECT plan_id,sequence,file_version_id,library_id,relative_path,
                    tape_relative_path,tape_id,cassette_number,physical_label,
                    size,sha256,copied_at
                FROM restore_plan_items_current;
                DROP TABLE restore_plan_items_current;
                """
            )
            catalog.connection.commit()
            catalog.create_block(
                "BLOCK-LATER",
                "LIB-A",
                "TAPE-B",
                "libraries/LIB-A/blocks/BLOCK-LATER",
                1,
                401,
            )
            later_version = catalog.record_file_version(
                "LIB-A",
                "BLOCK-LATER",
                "TAPE-B",
                PATH_FIXTURE[0][0],
                PATH_FIXTURE[0][1],
                401,
                401,
                "e" * 64,
            )
            catalog.complete_block("BLOCK-LATER")
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            columns = {
                row["name"]
                for row in catalog.connection.execute(
                    "PRAGMA table_info(restore_plan_items)"
                )
            }
            migrated = catalog.get_restore_plan(created.id)
        self.assertTrue({"volume_label", "block_id", "is_current"} <= columns)
        self.assertEqual(
            ("VOLUME-B",),
            tuple(item["volume_label"] for item in migrated["items"]),
        )
        self.assertEqual(
            ("BLOCK-NEW",),
            tuple(item["block_id"] for item in migrated["items"]),
        )
        self.assertEqual((None,), tuple(item["is_current"] for item in migrated["items"]))
        with self._io_guard():
            replay = await self.service.create_catalog_restore_plan(
                request, "task-6-migration", self.principal
            )
        self.assertEqual((None,), tuple(item.is_current for item in replay.items))
        self.assertEqual(created.id, replay.id)
        detail = self._read_without_catalog_mutation(
            lambda: self.service.get_catalog_file_version(later_version, self.principal)
        )
        self.assertTrue(detail.is_current)
        after_replay = self._table_snapshot()
        with self._io_guard():
            exact_replay = await self.service.create_catalog_restore_plan(
                request, "task-6-migration", self.principal
            )
        self.assertEqual(replay, exact_replay)
        self.assertEqual(after_replay, self._table_snapshot())
        self._assert_zero_io()


if __name__ == "__main__":
    unittest.main()
