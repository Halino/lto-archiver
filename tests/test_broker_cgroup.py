from __future__ import annotations

import hashlib
import os
import signal
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import ltobackup.broker.cgroup as broker_cgroup_module
from ltobackup.broker.cgroup import (
    CGROUP2_SUPER_MAGIC,
    PROC_SUPER_MAGIC,
    CgroupConflict,
    CgroupUnavailable,
    CgroupV2BrokerRoot,
)
from ltobackup.broker.cgroup import _write_control as real_write_control
from ltobackup.broker.store import BrokerStateConflict, BrokerStateStore, ScopeRecord
from ltobackup.tape.command_supervisor import BrokeredCgroupScopeReceipt
from tests.test_broker_store import BOOT_ID, NOW, _open_store


def _scope_digest(command_id: str, owner_generation: int) -> str:
    canonical = f"{owner_generation}:{command_id}".encode("ascii")
    return hashlib.sha256(b"lto-scope-v1\0" + canonical).hexdigest()


def _scope_name(command_id: str, owner_generation: int) -> str:
    return "command-" + _scope_digest(command_id, owner_generation)


def _receipt(
    command_id: str = "command-17", owner_generation: int = 9
) -> BrokeredCgroupScopeReceipt:
    return BrokeredCgroupScopeReceipt(
        protocol_version=1,
        command_id=command_id,
        owner_generation=owner_generation,
        request_nonce=b"r" * 32,
        scope_id="scope-17",
        scope_path_sha256=_scope_digest(command_id, owner_generation),
        broker_nonce=b"n" * 32,
        broker_proof=b"p" * 32,
        recursive_population=True,
        recursive_members=True,
        cgroup_kill=True,
    )


def _proc_stat(pid: int, start_ticks: int) -> bytes:
    fields = [b"S", *([b"0"] * 18), str(start_ticks).encode("ascii")]
    return str(pid).encode("ascii") + b" (worker ) name) " + b" ".join(fields) + b"\n"


class FakeCgroupKernel:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.writes: list[tuple[str, bytes]] = []
        self.after_write = None

    @staticmethod
    def _path(dir_fd: int, name: str) -> Path:
        return Path(os.readlink(f"/proc/self/fd/{dir_fd}")) / name

    @staticmethod
    def provision(path: Path) -> None:
        path.mkdir(mode=0o700, exist_ok=False)
        (path / "cgroup.controllers").write_text("cpu memory\n", encoding="ascii")
        (path / "cgroup.events").write_text("populated 0\nfrozen 0\n", encoding="ascii")
        (path / "cgroup.procs").write_text("", encoding="ascii")
        (path / "cgroup.kill").write_text("", encoding="ascii")
        (path / "cgroup.freeze").write_text("0\n", encoding="ascii")

    def make(self, name: str, *, dir_fd: int) -> None:
        self.provision(self._path(dir_fd, name))

    def write(self, name: str, payload: bytes, *, dir_fd: int) -> None:
        path = self._path(dir_fd, name)
        path.write_bytes(payload)
        self.writes.append((name, payload))
        if name in {"cgroup.freeze", "cgroup.procs"}:
            events = path.parent / "cgroup.events"
            try:
                values = {
                    line.split()[0]: line.split()[1]
                    for line in events.read_text(encoding="ascii").splitlines()
                    if len(line.split()) == 2
                }
            except (OSError, UnicodeError):
                values = {}
            values.setdefault("populated", "0")
            values.setdefault("frozen", "0")
            if name == "cgroup.freeze":
                values["frozen"] = payload.strip().decode("ascii")
            else:
                values["populated"] = "1" if payload.strip() else "0"
            events.write_text(
                f"populated {values['populated']}\nfrozen {values['frozen']}\n",
                encoding="ascii",
            )
        if name == "cgroup.kill":
            for members in path.parent.rglob("cgroup.procs"):
                members.write_text("", encoding="ascii")
            for events in path.parent.rglob("cgroup.events"):
                values = {
                    line.split()[0]: line.split()[1]
                    for line in events.read_text(encoding="ascii").splitlines()
                }
                events.write_text(
                    f"populated 0\nfrozen {values.get('frozen', '0')}\n",
                    encoding="ascii",
                )
        if self.after_write is not None:
            self.after_write(name, payload)

    def remove(self, name: str, *, dir_fd: int) -> None:
        path = self._path(dir_fd, name)
        for child in path.iterdir():
            if child.is_file() or child.is_symlink():
                child.unlink()
        path.rmdir()


class CgroupBrokerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "delegated"
        self.proc = self.base / "proc"
        self.proc.mkdir()
        (self.proc / "sys/kernel/random").mkdir(parents=True)
        self.boot_id_path = self.proc / "sys/kernel/random/boot_id"
        self.boot_id_path.write_text(BOOT_ID + "\n", encoding="ascii")
        FakeCgroupKernel.provision(self.root)
        self.kernel = FakeCgroupKernel(self.root)
        self.store_path = self.base / "state.db"
        self.store = _open_store(self.store_path, boot_id=BOOT_ID, clock=lambda: NOW)
        self.addCleanup(self.store.close)
        self.receipt = _receipt()
        self.record = self.store.create_scope(self.receipt)

        def filesystem_magic(fd: int) -> int:
            target = Path(os.readlink(f"/proc/self/fd/{fd}"))
            if target == self.root:
                return CGROUP2_SUPER_MAGIC
            if target == self.proc:
                return PROC_SUPER_MAGIC
            raise AssertionError(f"unexpected filesystem probe: {target.name}")

        self.patches = (
            patch(
                "ltobackup.broker.cgroup._filesystem_magic",
                side_effect=filesystem_magic,
            ),
            patch("ltobackup.broker.cgroup._secure_root", return_value=True),
            patch("ltobackup.broker.cgroup._make_cgroup", side_effect=self.kernel.make),
            patch(
                "ltobackup.broker.cgroup._write_control", side_effect=self.kernel.write
            ),
            patch(
                "ltobackup.broker.cgroup._remove_cgroup", side_effect=self.kernel.remove
            ),
        )
        for active in self.patches:
            active.start()
            self.addCleanup(active.stop)

    def open_engine(self) -> CgroupV2BrokerRoot:
        engine = CgroupV2BrokerRoot.open(self.root, self.proc, self.boot_id_path)
        self.addCleanup(engine.close)
        return engine

    def create_scope(self) -> tuple[CgroupV2BrokerRoot, ScopeRecord, Path]:
        engine = self.open_engine()
        bound = engine.create(self.record, self.store)
        scope_path = self.root / _scope_name(
            self.record.command_id, self.record.owner_generation
        )
        return engine, bound, scope_path

    def add_process(
        self, pid: int, start_ticks: int, *, uid: int | None = None
    ) -> Path:
        process = self.proc / str(pid)
        process.mkdir()
        (process / "stat").write_bytes(_proc_stat(pid, start_ticks))
        if uid is not None and uid != os.getuid():
            self.skipTest("fake proc UID changes require ownership privileges")
        return process


class CgroupRootOpeningTests(CgroupBrokerTestCase):
    def test_proc_ancestors_use_opath_and_only_final_file_is_read(self):
        self.assertTrue(hasattr(os, "O_PATH"))
        proc_fd = os.open(
            self.proc,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        self.addCleanup(os.close, proc_fd)
        real_open = os.open
        calls: list[tuple[str, int]] = []

        def observe_open(path, flags, *args, **kwargs):
            calls.append((os.fsdecode(path), flags))
            return real_open(path, flags, *args, **kwargs)

        with patch.object(broker_cgroup_module.os, "open", side_effect=observe_open):
            payload = broker_cgroup_module._read_relative_file(
                proc_fd, ("sys", "kernel", "random", "boot_id")
            )

        self.assertEqual((BOOT_ID + "\n").encode("ascii"), payload)
        self.assertEqual(["sys", "kernel", "random", "boot_id"], [p for p, _ in calls])
        for _, flags in calls[:-1]:
            self.assertTrue(flags & os.O_PATH)
            self.assertTrue(flags & os.O_DIRECTORY)
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertTrue(flags & os.O_CLOEXEC)
        self.assertFalse(calls[-1][1] & os.O_PATH)
        self.assertFalse(calls[-1][1] & os.O_DIRECTORY)
        self.assertTrue(calls[-1][1] & os.O_NOFOLLOW)
        self.assertTrue(calls[-1][1] & os.O_CLOEXEC)

    def test_open_requires_exact_filesystems_boot_and_control_contract(self):
        for missing in ("cgroup.controllers", "cgroup.events", "cgroup.kill"):
            target = self.root / missing
            contents = target.read_bytes()
            target.unlink()
            with (
                self.subTest(missing=missing),
                self.assertRaisesRegex(
                    CgroupUnavailable, r"^command broker cgroup unavailable$"
                ),
            ):
                CgroupV2BrokerRoot.open(self.root, self.proc, self.boot_id_path)
            target.write_bytes(contents)

        with (
            patch("ltobackup.broker.cgroup._filesystem_magic", return_value=0xEF53),
            self.assertRaises(CgroupUnavailable),
        ):
            CgroupV2BrokerRoot.open(self.root, self.proc, self.boot_id_path)

        self.boot_id_path.write_text("not-a-boot-id\n", encoding="ascii")
        with self.assertRaises(CgroupUnavailable):
            CgroupV2BrokerRoot.open(self.root, self.proc, self.boot_id_path)

    def test_write_only_cgroup_kill_is_probed_for_write_at_root_and_scope(self):
        real_open = os.open
        kill_access_modes: list[int] = []

        def kernel_open(path, flags, *args, **kwargs):
            if path == "cgroup.kill":
                access_mode = flags & os.O_ACCMODE
                kill_access_modes.append(access_mode)
                if access_mode != os.O_WRONLY:
                    raise PermissionError("cgroup.kill is write-only")
            return real_open(path, flags, *args, **kwargs)

        with patch("ltobackup.broker.cgroup.os.open", side_effect=kernel_open):
            engine = self.open_engine()
            engine.create(self.record, self.store)

        self.assertEqual(kill_access_modes, [os.O_WRONLY, os.O_WRONLY])

    def test_open_rejects_symlink_component_and_redacts_paths(self):
        real = self.base / "real-root"
        FakeCgroupKernel.provision(real)
        linked = self.base / "linked-root"
        linked.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(
            CgroupUnavailable, r"^command broker cgroup unavailable$"
        ) as caught:
            CgroupV2BrokerRoot.open(linked, self.proc, self.boot_id_path)
        self.assertNotIn(str(linked), str(caught.exception))

    def test_real_control_writer_rejects_symlink_without_touching_target(self):
        directory = self.base / "writer"
        directory.mkdir()
        target = self.base / "outside"
        target.write_bytes(b"unchanged")
        (directory / "cgroup.procs").symlink_to(target)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, directory_fd)
        with self.assertRaises(OSError):
            real_write_control("cgroup.procs", b"17\n", dir_fd=directory_fd)
        self.assertEqual(target.read_bytes(), b"unchanged")


class CgroupScopeBindingTests(CgroupBrokerTestCase):
    def test_create_is_exclusive_deterministic_and_open_revalidates_inode(self):
        engine, bound, scope_path = self.create_scope()
        self.assertEqual(scope_path.name, "command-" + self.receipt.scope_path_sha256)
        self.assertEqual(
            (bound.cgroup_device, bound.cgroup_inode),
            (scope_path.stat().st_dev, scope_path.stat().st_ino),
        )
        self.assertEqual(engine.open(bound).inode, scope_path.stat().st_ino)
        with self.assertRaises(CgroupConflict):
            engine.create(self.record, self.store)

    def test_restart_accepts_same_inode_and_rejects_same_name_replacement(self):
        engine, bound, scope_path = self.create_scope()
        engine.close()
        self.store.close()

        reopened_store = _open_store(
            self.store_path, boot_id=BOOT_ID, clock=lambda: NOW
        )
        self.addCleanup(reopened_store.close)
        persisted = reopened_store.open_scope(self.receipt)
        reopened = self.open_engine()
        self.assertEqual(reopened.open(persisted).inode, bound.cgroup_inode)

        old = self.root / "retained-old-inode"
        scope_path.rename(old)
        FakeCgroupKernel.provision(scope_path)
        with self.assertRaises(CgroupConflict):
            reopened.open(persisted)

    def test_symlink_swap_traversal_wrong_digest_and_boot_change_fail_closed(self):
        engine, bound, scope_path = self.create_scope()
        old = self.root / "old-scope"
        scope_path.rename(old)
        scope_path.symlink_to(old, target_is_directory=True)
        with self.assertRaises(CgroupConflict):
            engine.open(bound)

        for mutation in (
            replace(bound, command_id="../escape"),
            replace(bound, scope_path_sha256="f" * 64),
            replace(bound, scope_id="../scope"),
        ):
            with self.subTest(mutation=mutation), self.assertRaises(CgroupConflict):
                engine.open(mutation)

        self.boot_id_path.write_text(
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n", encoding="ascii"
        )
        with self.assertRaises(CgroupConflict):
            engine.open(bound)

    def test_failed_durable_binding_removes_new_empty_scope(self):
        engine = self.open_engine()
        scope_path = self.root / _scope_name(
            self.record.command_id, self.record.owner_generation
        )
        with (
            patch.object(
                BrokerStateStore,
                "bind_cgroup",
                side_effect=BrokerStateConflict,
            ),
            self.assertRaises(CgroupConflict),
        ):
            engine.create(self.record, self.store)

        self.assertFalse(scope_path.exists())
        persisted = self.store.open_scope(self.receipt)
        self.assertEqual(
            (persisted.cgroup_device, persisted.cgroup_inode), (None, None)
        )


class CgroupRecursiveValidationTests(CgroupBrokerTestCase):
    def test_validation_is_recursive_sorted_unique_and_checks_population(self):
        engine, bound, scope_path = self.create_scope()
        child = scope_path / "child"
        FakeCgroupKernel.provision(child)
        (scope_path / "cgroup.procs").write_text("31\n29\n", encoding="ascii")
        (child / "cgroup.procs").write_text("29\n37\n", encoding="ascii")
        (scope_path / "cgroup.events").write_text(
            "populated 1\nfrozen 0\n", encoding="ascii"
        )
        (child / "cgroup.events").write_text(
            "populated 1\nfrozen 0\n", encoding="ascii"
        )

        validation = engine.validate(bound)
        self.assertTrue(validation.populated)
        self.assertEqual(validation.member_pids, (29, 31, 37))

        (scope_path / "cgroup.events").write_text(
            "populated 0\nfrozen 0\n", encoding="ascii"
        )
        with self.assertRaises(CgroupConflict):
            engine.validate(bound)

    def test_malformed_descendant_controls_and_nonempty_release_fail_closed(self):
        engine, bound, scope_path = self.create_scope()
        child = scope_path / "child"
        FakeCgroupKernel.provision(child)
        (child / "cgroup.procs").write_text("not-a-pid\n", encoding="ascii")
        with self.assertRaises(CgroupConflict):
            engine.validate(bound)

        (child / "cgroup.procs").write_text("71\n", encoding="ascii")
        (scope_path / "cgroup.events").write_text(
            "populated 1\nfrozen 0\n", encoding="ascii"
        )
        (child / "cgroup.events").write_text(
            "populated 1\nfrozen 0\n", encoding="ascii"
        )
        with self.assertRaises(CgroupConflict):
            engine.release(bound)

    def test_empty_recursive_release_is_deepest_first_and_idempotent_in_process(self):
        engine, bound, scope_path = self.create_scope()
        child = scope_path / "child"
        grandchild = child / "grandchild"
        FakeCgroupKernel.provision(child)
        FakeCgroupKernel.provision(grandchild)

        engine.release(bound)
        self.assertFalse(scope_path.exists())
        engine.release(bound)

    def test_partial_deepest_first_release_is_retryable_without_fd_leak(self):
        engine, bound, scope_path = self.create_scope()
        child = scope_path / "child"
        grandchild = child / "grandchild"
        FakeCgroupKernel.provision(child)
        FakeCgroupKernel.provision(grandchild)
        descriptors_before = len(tuple(Path("/proc/self/fd").iterdir()))
        failed = False

        def fail_once(name: str, *, dir_fd: int) -> None:
            nonlocal failed
            if name == "child" and not failed:
                failed = True
                raise OSError("injected partial release")
            self.kernel.remove(name, dir_fd=dir_fd)

        with (
            patch("ltobackup.broker.cgroup._remove_cgroup", side_effect=fail_once),
            self.assertRaises(CgroupConflict),
        ):
            engine.release(bound)

        self.assertFalse(grandchild.exists())
        self.assertTrue(child.exists())
        self.assertTrue(scope_path.exists())
        self.assertEqual(
            len(tuple(Path("/proc/self/fd").iterdir())), descriptors_before
        )
        engine.release(bound)
        self.assertFalse(scope_path.exists())

    def test_descendant_symlink_and_missing_scope_kill_are_conflicts(self):
        engine, bound, scope_path = self.create_scope()
        (scope_path / "host-link").symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(CgroupConflict):
            engine.validate(bound)
        (scope_path / "host-link").unlink()
        (scope_path / "cgroup.kill").unlink()
        with self.assertRaises(CgroupConflict):
            engine.kill(bound)


class CgroupAttachAndSignalTests(CgroupBrokerTestCase):
    def test_attach_checks_uid_start_ticks_and_recursive_membership(self):
        engine, bound, scope_path = self.create_scope()
        self.add_process(4713, 77001)
        with self.assertRaises(CgroupConflict):
            engine.attach(
                bound,
                4713,
                daemon_uid=os.getuid() + 1,
                store=self.store,
            )
        self.assertEqual((scope_path / "cgroup.procs").read_text(), "")

        self.add_process(4711, 88001)
        proof = engine.attach(bound, 4711, daemon_uid=os.getuid(), store=self.store)
        self.assertEqual((proof.pid, proof.start_ticks), (4711, 88001))
        self.assertEqual((scope_path / "cgroup.procs").read_text(), "4711\n")
        attached = self.store.open_scope(self.receipt)
        self.assertEqual((attached.pid, attached.process_start_ticks), (4711, 88001))

        self.kernel.writes.clear()
        self.assertEqual(
            engine.attach(bound, 4711, daemon_uid=os.getuid(), store=self.store),
            proof,
        )
        self.assertNotIn(
            "cgroup.procs", [name for name, _payload in self.kernel.writes]
        )

        self.kernel.writes.clear()
        with self.assertRaises(CgroupConflict):
            engine.attach(bound, 4712, daemon_uid=os.getuid(), store=self.store)
        self.assertEqual(self.kernel.writes, [])

    def test_postwrite_start_tick_failure_kills_quiesces_and_marks_broken(self):
        engine, bound, scope_path = self.create_scope()
        process = self.add_process(4721, 99001)
        self.kernel.after_write = lambda name, payload: (
            (process / "stat").write_bytes(_proc_stat(4721, 99002))
            if name == "cgroup.procs"
            else None
        )

        with self.assertRaises(CgroupConflict):
            engine.attach(bound, 4721, daemon_uid=os.getuid(), store=self.store)

        self.assertEqual((scope_path / "cgroup.procs").read_text(), "")
        self.assertIn(("cgroup.kill", b"1\n"), self.kernel.writes)
        self.assertEqual(self.store.open_scope(self.receipt).state, "BROKEN")

        self.store.close()
        reopened = _open_store(self.store_path, boot_id=BOOT_ID, clock=lambda: NOW)
        self.addCleanup(reopened.close)
        persisted = reopened.open_scope(self.receipt)
        self.assertEqual(persisted.state, "BROKEN")
        self.assertEqual((persisted.pid, persisted.process_start_ticks), (None, None))

    def test_exact_retry_rechecks_identity_after_recursive_validation(self):
        engine, bound, scope_path = self.create_scope()
        process = self.add_process(4723, 99021)
        engine.attach(bound, 4723, daemon_uid=os.getuid(), store=self.store)
        attached = self.store.open_scope(self.receipt)
        original_validate = engine.validate
        reused = False

        def reuse_during_validation(record: ScopeRecord):
            nonlocal reused
            validation = original_validate(record)
            if not reused:
                reused = True
                (process / "stat").write_bytes(_proc_stat(4723, 99022))
            return validation

        self.kernel.writes.clear()
        with (
            patch.object(engine, "validate", side_effect=reuse_during_validation),
            self.assertRaises(CgroupConflict),
        ):
            engine.attach(attached, 4723, daemon_uid=os.getuid(), store=self.store)

        self.assertNotIn(
            "cgroup.procs", [name for name, _payload in self.kernel.writes]
        )
        self.assertIn(("cgroup.kill", b"1\n"), self.kernel.writes)
        self.assertEqual((scope_path / "cgroup.procs").read_text(), "")
        self.assertEqual(self.store.open_scope(self.receipt).state, "BROKEN")

    def test_initial_attach_rechecks_identity_after_recursive_validation(self):
        engine, bound, scope_path = self.create_scope()
        process = self.add_process(4724, 99031)
        original_validate = engine.validate
        reused = False

        def reuse_after_populated_validation(record: ScopeRecord):
            nonlocal reused
            validation = original_validate(record)
            if validation.member_pids and not reused:
                reused = True
                (process / "stat").write_bytes(_proc_stat(4724, 99032))
            return validation

        with (
            patch.object(
                engine, "validate", side_effect=reuse_after_populated_validation
            ),
            self.assertRaises(CgroupConflict),
        ):
            engine.attach(bound, 4724, daemon_uid=os.getuid(), store=self.store)

        self.assertIn(("cgroup.kill", b"1\n"), self.kernel.writes)
        self.assertEqual((scope_path / "cgroup.procs").read_text(), "")
        self.assertEqual(self.store.open_scope(self.receipt).state, "BROKEN")

    def test_initial_attach_rejects_extra_recursive_member(self):
        engine, bound, scope_path = self.create_scope()
        self.add_process(4725, 99041)
        child = scope_path / "unexpected-child"

        def add_unexpected_member(name: str, _payload: bytes) -> None:
            if name == "cgroup.procs":
                FakeCgroupKernel.provision(child)
                (child / "cgroup.procs").write_text("4726\n", encoding="ascii")
                (child / "cgroup.events").write_text(
                    "populated 1\nfrozen 0\n", encoding="ascii"
                )

        self.kernel.after_write = add_unexpected_member
        with self.assertRaises(CgroupConflict):
            engine.attach(bound, 4725, daemon_uid=os.getuid(), store=self.store)

        self.assertIn(("cgroup.kill", b"1\n"), self.kernel.writes)
        self.assertEqual((scope_path / "cgroup.procs").read_text(), "")
        self.assertEqual((child / "cgroup.procs").read_text(), "")
        self.assertEqual(self.store.open_scope(self.receipt).state, "BROKEN")

    def test_restart_window_with_unpersisted_member_is_contained_not_reattached(self):
        engine, bound, scope_path = self.create_scope()
        self.add_process(4722, 99011)
        (scope_path / "cgroup.procs").write_text("4722\n", encoding="ascii")
        (scope_path / "cgroup.events").write_text(
            "populated 1\nfrozen 0\n", encoding="ascii"
        )

        with self.assertRaises(CgroupConflict):
            engine.attach(bound, 4722, daemon_uid=os.getuid(), store=self.store)

        persisted = self.store.open_scope(self.receipt)
        self.assertEqual(persisted.state, "BROKEN")
        self.assertEqual((persisted.pid, persisted.process_start_ticks), (None, None))
        self.assertEqual((scope_path / "cgroup.procs").read_text(), "")

    def test_postwrite_membership_failure_is_contained_and_persisted_broken(self):
        engine, bound, scope_path = self.create_scope()
        self.add_process(4731, 99101)

        def remove_membership_after_write(name: str, _payload: bytes) -> None:
            if name == "cgroup.procs":
                (scope_path / "cgroup.procs").write_text("", encoding="ascii")
                (scope_path / "cgroup.events").write_text(
                    "populated 0\nfrozen 0\n", encoding="ascii"
                )

        self.kernel.after_write = remove_membership_after_write
        with self.assertRaises(CgroupConflict):
            engine.attach(bound, 4731, daemon_uid=os.getuid(), store=self.store)
        self.assertEqual(self.store.open_scope(self.receipt).state, "BROKEN")
        self.assertIn(("cgroup.kill", b"1\n"), self.kernel.writes)

    def test_failed_kill_after_uncertain_attach_holds_frozen_and_marks_broken(self):
        engine, bound, scope_path = self.create_scope()
        process = self.add_process(4741, 99201)
        descriptors_before = len(tuple(Path("/proc/self/fd").iterdir()))

        def race_start_ticks(name: str, _payload: bytes) -> None:
            if name == "cgroup.procs":
                (process / "stat").write_bytes(_proc_stat(4741, 99202))

        self.kernel.after_write = race_start_ticks

        def fail_kill(name: str, payload: bytes, *, dir_fd: int) -> None:
            if name == "cgroup.kill":
                raise OSError("injected kill failure")
            self.kernel.write(name, payload, dir_fd=dir_fd)

        with (
            patch("ltobackup.broker.cgroup._write_control", side_effect=fail_kill),
            self.assertRaises(CgroupUnavailable),
        ):
            engine.attach(bound, 4741, daemon_uid=os.getuid(), store=self.store)

        self.assertEqual(self.store.open_scope(self.receipt).state, "BROKEN")
        self.assertIn(("cgroup.freeze", b"1\n"), self.kernel.writes)
        self.assertEqual(
            (scope_path / "cgroup.events").read_text(encoding="ascii"),
            "populated 1\nfrozen 1\n",
        )
        self.assertEqual(
            len(tuple(Path("/proc/self/fd").iterdir())), descriptors_before
        )

    def test_signal_freezes_revalidates_exact_members_and_only_admits_sigterm(self):
        engine, bound, scope_path = self.create_scope()
        self.add_process(4811, 88101)
        bound = self.store.attach_cgroup_process(bound, pid=4811, start_ticks=88101)
        (scope_path / "cgroup.procs").write_text("4811\n", encoding="ascii")
        (scope_path / "cgroup.events").write_text(
            "populated 1\nfrozen 0\n", encoding="ascii"
        )
        sent: list[tuple[int, int]] = []

        def open_pidfd(pid: int) -> int:
            self.assertEqual(pid, 4811)
            return os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)

        with (
            patch("ltobackup.broker.cgroup._pidfd_open", side_effect=open_pidfd),
            patch(
                "ltobackup.broker.cgroup._pidfd_send_signal",
                side_effect=lambda fd, signum: sent.append((fd, signum)),
            ),
        ):
            engine.signal(
                bound,
                signal.SIGTERM,
                daemon_uid=os.getuid(),
                store=self.store,
            )

        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0][1], signal.SIGTERM)
        self.assertEqual(
            [
                payload
                for name, payload in self.kernel.writes
                if name == "cgroup.freeze"
            ],
            [b"1\n", b"0\n"],
        )
        with self.assertRaises(CgroupConflict):
            engine.signal(
                bound,
                signal.SIGINT,
                daemon_uid=os.getuid(),
                store=self.store,
            )

    def test_kill_uses_cgroup_kill_and_never_process_group_fallback(self):
        engine, bound, scope_path = self.create_scope()
        with patch("ltobackup.broker.cgroup.os.killpg") as killpg:
            engine.kill(bound)
        killpg.assert_not_called()
        self.assertEqual((scope_path / "cgroup.kill").read_bytes(), b"1\n")

    def test_signal_rejects_pid_reuse_after_pidfd_open_and_always_unfreezes(self):
        engine, bound, scope_path = self.create_scope()
        process = self.add_process(4911, 99101)
        bound = self.store.attach_cgroup_process(bound, pid=4911, start_ticks=99101)
        (scope_path / "cgroup.procs").write_text("4911\n", encoding="ascii")
        (scope_path / "cgroup.events").write_text(
            "populated 1\nfrozen 0\n", encoding="ascii"
        )
        sent: list[int] = []

        def reuse_after_pidfd(_pid: int) -> int:
            descriptor = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
            (process / "stat").write_bytes(_proc_stat(4911, 99102))
            return descriptor

        with (
            patch("ltobackup.broker.cgroup._pidfd_open", side_effect=reuse_after_pidfd),
            patch(
                "ltobackup.broker.cgroup._pidfd_send_signal",
                side_effect=lambda _fd, signum: sent.append(signum),
            ),
            self.assertRaises(CgroupConflict),
        ):
            engine.signal(
                bound,
                signal.SIGTERM,
                daemon_uid=os.getuid(),
                store=self.store,
            )

        self.assertEqual(sent, [])
        self.assertEqual(
            (scope_path / "cgroup.events").read_text(encoding="ascii"),
            "populated 1\nfrozen 0\n",
        )

    def test_freeze_confirmation_timeout_still_requests_and_confirms_thaw(self):
        engine, bound, scope_path = self.create_scope()

        def keep_unfrozen(name: str, payload: bytes) -> None:
            if name == "cgroup.freeze" and payload == b"1\n":
                (scope_path / "cgroup.events").write_text(
                    "populated 0\nfrozen 0\n", encoding="ascii"
                )

        self.kernel.after_write = keep_unfrozen
        with (
            patch(
                "ltobackup.broker.cgroup.time.monotonic",
                side_effect=(0.0, 2.0, 3.0),
            ),
            self.assertRaises(CgroupConflict),
        ):
            engine.signal(
                bound,
                signal.SIGTERM,
                daemon_uid=os.getuid(),
                store=self.store,
            )

        self.assertEqual(
            [
                payload
                for name, payload in self.kernel.writes
                if name == "cgroup.freeze"
            ],
            [b"1\n", b"0\n"],
        )
        self.assertEqual(
            (scope_path / "cgroup.events").read_text(encoding="ascii"),
            "populated 0\nfrozen 0\n",
        )
        self.assertEqual(self.store.open_scope(self.receipt).state, "ACTIVE")

    def test_malformed_freeze_confirmation_still_confirms_thaw(self):
        engine, bound, scope_path = self.create_scope()

        def corrupt_freeze_events(name: str, payload: bytes) -> None:
            if name == "cgroup.freeze" and payload == b"1\n":
                (scope_path / "cgroup.events").write_text(
                    "malformed\n", encoding="ascii"
                )

        self.kernel.after_write = corrupt_freeze_events
        with self.assertRaises(CgroupConflict):
            engine.signal(
                bound,
                signal.SIGTERM,
                daemon_uid=os.getuid(),
                store=self.store,
            )

        self.assertEqual(
            [
                payload
                for name, payload in self.kernel.writes
                if name == "cgroup.freeze"
            ],
            [b"1\n", b"0\n"],
        )
        self.assertEqual(
            (scope_path / "cgroup.events").read_text(encoding="ascii"),
            "populated 0\nfrozen 0\n",
        )
        self.assertEqual(self.store.open_scope(self.receipt).state, "ACTIVE")

    def test_unconfirmed_thaw_marks_broken_and_kills_scope(self):
        engine, bound, scope_path = self.create_scope()

        def remain_frozen_after_thaw(name: str, payload: bytes) -> None:
            if name == "cgroup.freeze" and payload == b"0\n":
                (scope_path / "cgroup.events").write_text(
                    "populated 0\nfrozen 1\n", encoding="ascii"
                )

        self.kernel.after_write = remain_frozen_after_thaw
        with (
            patch(
                "ltobackup.broker.cgroup.time.monotonic",
                side_effect=(0.0, 2.0, 4.0, 5.0),
            ),
            self.assertRaises(CgroupConflict),
        ):
            engine.signal(
                bound,
                signal.SIGTERM,
                daemon_uid=os.getuid(),
                store=self.store,
            )

        self.assertEqual(self.store.open_scope(self.receipt).state, "BROKEN")
        self.assertIn(("cgroup.kill", b"1\n"), self.kernel.writes)
        self.assertEqual((scope_path / "cgroup.procs").read_text(), "")

    def test_binding_representation_redacts_device_and_inode(self):
        engine, bound, _scope_path = self.create_scope()
        representation = repr(engine.open(bound))
        self.assertNotIn(str(bound.cgroup_device), representation)
        self.assertNotIn(str(bound.cgroup_inode), representation)


if __name__ == "__main__":
    unittest.main()
