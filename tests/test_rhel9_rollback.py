from __future__ import annotations

import hashlib
import ctypes
import importlib.util
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging" / "scripts" / "rollback-rhel9.py"
SNAPSHOT_IDS = (
    "configuration",
    "application_state",
    "command_broker_state",
    "share_broker_state",
    "web_auth_state",
    "custom_web_unit",
    "systemd_dropins",
)
LTFS_SNAPSHOT_PATHS = {
    "ltfs_device_configuration": "lto-ltfs",
    "ltfs_configuration": "ltfs.conf",
    "ltfs_configuration_rpmnew": "ltfs.conf.rpmnew",
    "ltfs_configuration_rpmsave": "ltfs.conf.rpmsave",
    "ltfs_local_configuration": "ltfs.conf.local",
    "ltfs_local_configuration_rpmnew": "ltfs.conf.local.rpmnew",
    "ltfs_local_configuration_rpmsave": "ltfs.conf.local.rpmsave",
}


def _load_module():
    spec = importlib.util.spec_from_file_location("rollback_rhel9", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load rollback runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeRollbackHost:
    def __init__(self, module, root: Path) -> None:
        self.module = module
        self.root = root
        self.root_user = True
        self.secure_parent = True
        self.available = 100 * 1024**3
        self.binding = b"private-machine-id"
        self.nevras = {
            "lto-archiver": "lto-archiver-0.11.27-141.el9.noarch",
            "lto-archiver-python-runtime": (
                "lto-archiver-python-runtime-0.11.27-3.el9.x86_64"
            ),
            "lto-ltfs": "lto-ltfs-0.1.0-21.el9.x86_64",
        }
        self.rpm_evidence: tuple[object, ...] = ()
        self.snapshot_bytes = {
            name: 1024 for name in (*SNAPSHOT_IDS, *LTFS_SNAPSHOT_PATHS)
        }
        self.bundle_secure = True
        self.rollback_rpm_authority = True
        self.state_valid = True
        self.rpm_valid = True
        self.snapshot_valid = True
        self.custom_hash = "c" * 64
        self.calls: list[str] = []
        self.swap_calls: list[str] = []
        self.reverse_calls: list[str] = []
        self.fail_swap: str | None = None
        self.old_health = True
        self.metadata_drift = False
        self.published = False
        self.fsync_calls = 0
        self.masked = False
        self.source_backup_prepared = False
        self.source_catalog_bytes = b"stopped-schema-40-catalog"
        self.restore_capacity = True
        self.artifact_lease_active = False
        self.artifact_lease_busy = False

    def is_root(self) -> bool:
        return self.root_user

    def parent_is_secure(self, parent: Path) -> bool:
        self.calls.append("parent-security")
        return self.secure_parent

    def available_bytes(self, parent: Path) -> int:
        self.calls.append("capacity")
        return self.available

    def verify_restore_capacity(self, bundle: Path, manifest) -> None:
        self.calls.append("restore-capacity")
        if not self.restore_capacity:
            raise self.module.RollbackError("restore capacity is insufficient")

    @contextmanager
    def artifact_lease(self, bundle: Path):
        if self.artifact_lease_busy:
            raise self.module.RollbackError("registered bundle lease is busy")
        self.calls.append("artifact-lease-enter")
        self.artifact_lease_active = True
        try:
            yield
        finally:
            self.artifact_lease_active = False
            self.calls.append("artifact-lease-exit")

    def host_binding_material(self) -> bytes:
        return self.binding

    def installed_nevras(self):
        return self.nevras

    def captured_installed_package_state(self):
        app_row = "S.5....T.  c /etc/lto-archiver/config.toml"
        driver_row = "S.5....T.  c /etc/lto-ltfs/device.json"
        state = {
            "packages": {
                package: {
                    "installed_file_metadata_sha256": (
                        "1" * 64
                        if package == "lto-ltfs"
                        else _sha((package + "-metadata").encode())
                    ),
                    "nevra": nevra,
                    "rpm_verify_exit": (
                        1 if package in {"lto-archiver", "lto-ltfs"} else 0
                    ),
                    "rpm_verify_stdout_sha256": _sha(
                        (app_row + "\n").encode()
                        if package == "lto-archiver"
                        else (driver_row + "\n").encode()
                        if package == "lto-ltfs"
                        else b""
                    ),
                    "rpm_verify_rows": (
                        [app_row]
                        if package == "lto-archiver"
                        else [driver_row]
                        if package == "lto-ltfs"
                        else []
                    ),
                }
                for package, nevra in self.nevras.items()
            },
            "schema": 1,
        }
        if self.metadata_drift:
            state["packages"]["lto-archiver"][
                "installed_file_metadata_sha256"
            ] = "0" * 64
        return state

    def inspect_rollback_rpms(self, directory: Path):
        self.calls.append("rpm-closure")
        return self.rpm_evidence

    def rollback_rpm_authority_ok(self, directory: Path, filenames):
        self.calls.append("rpm-authority")
        return self.rollback_rpm_authority

    def snapshot_sources(self):
        return tuple(
            self.module.SnapshotSource(name, size)
            for name, size in self.snapshot_bytes.items()
        )

    def prepare_source_catalog_backup(self, parent: Path):
        self.calls.append("prepare-source-backup")
        self.source_backup_prepared = True
        staging = Path(tempfile.mkdtemp(prefix=".source-recovery-", dir=parent))
        backup = staging / (
            "20260831T120000000000Z-abcdef123456-p-v40-"
            "0123456789abcdef.sqlite3"
        )
        backup.write_bytes(b"sqlite-backup-schema-40")
        return self.module.PreparedSourceBackup(
            path=backup,
            source_schema=40,
            catalog_sha256=_sha(self.source_catalog_bytes),
            backup_sha256=_sha(backup.read_bytes()),
        )

    def validate_prepared_source(self, prepared) -> bool:
        try:
            return (
                prepared.source_schema == 40
                and prepared.catalog_sha256 == _sha(self.source_catalog_bytes)
                and prepared.backup_sha256 == _sha(prepared.path.read_bytes())
            )
        except (AttributeError, OSError):
            return False

    def copy_prepared_source(self, prepared, destination: Path) -> None:
        destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        destination.write_bytes(prepared.path.read_bytes())

    def verify_protected_source(self, bundle: Path, manifest) -> bool:
        try:
            selected = bundle / manifest.protected_backup_relative_path
            application = next(
                row for row in manifest.snapshots
                if row.identity == "application_state"
            )
            catalog = next(
                row for row in application.files
                if row.relative_path == "catalog.db"
            )
            return (
                manifest.source_catalog_schema == 40
                and catalog.sha256 == manifest.source_catalog_sha256
                and _sha(selected.read_bytes()) == manifest.protected_backup_sha256
            )
        except (OSError, StopIteration):
            return False

    def copy_snapshot(self, source, destination: Path):
        self.calls.append(f"copy:{source.identity}")
        destination.mkdir(parents=True, mode=0o700)
        payload = (
            self.source_catalog_bytes
            if source.identity == "application_state"
            else f"secret-{source.identity}".encode()
        )
        relative = "catalog.db" if source.identity == "application_state" else "payload.bin"
        path = destination / relative
        path.write_bytes(payload)
        return self.module.SnapshotEvidence(
            identity=source.identity,
            logical_bytes=source.logical_bytes,
            files=(
                self.module.FileEvidence(
                    relative_path=relative,
                    sha256=_sha(payload),
                    size=len(payload),
                    mode=0o600,
                    uid=0,
                    gid=0,
                    acl_sha256="a" * 64,
                    xattr_sha256="b" * 64,
                    selinux_sha256="c" * 64,
                ),
            ),
            directories=(
                self.module.DirectoryEvidence(
                    relative_path=".",
                    mode=0o700,
                    uid=0,
                    gid=0,
                    acl_sha256="a" * 64,
                    xattr_sha256="b" * 64,
                    selinux_sha256="c" * 64,
                ),
            ),
        )

    def check_copied_state(self, snapshots: Path):
        self.calls.append("state-checks-read-only")
        return tuple(
            self.module.StateCheck(name, True, True, True)
            for name in self.module.REQUIRED_STATE_CHECKS
        )

    def custom_web_unit_sha256(self):
        return self.custom_hash

    def captured_enablement(self):
        return {
            unit: (
                "enabled"
                if unit
                in {
                    "lto-archiver-command-broker.socket",
                    "lto-archiver-share-broker.socket",
                    "lto-archiverd.socket",
                    "lto-archiver-web.service",
                }
                else "static"
            )
            for unit in self.module.STOP_UNITS
        }

    def firewall_observation_digest(self):
        return "d" * 64

    def copy_bundle_tools(self, destination: Path):
        self.calls.append("copy-tools")
        destination.mkdir(parents=True, mode=0o700)
        result = {}
        for name in (
            "rollback-rhel9.py",
            "verify-deployment-rhel9.py",
            "rpm-verify-policy.json",
            "journal-policy.json",
        ):
            data = f"tool:{name}\n".encode()
            (destination / name).write_bytes(data)
            result[name] = _sha(data)
        return result

    def tool_versions(self):
        return {"python": "3.11", "rpm": "4.16"}

    def verify_bundle_security(self, bundle: Path) -> bool:
        return self.bundle_secure

    def verify_rpm_evidence(self, evidence) -> bool:
        return self.rpm_valid

    def verify_snapshot_evidence(self, bundle: Path, evidence) -> bool:
        if not self.snapshot_valid:
            return False
        for snapshot in evidence:
            for record in snapshot.files:
                path = bundle / "snapshots" / snapshot.identity / record.relative_path
                if not path.is_file() or _sha(path.read_bytes()) != record.sha256:
                    return False
        return True

    def verify_copied_state(self, bundle: Path, checks) -> bool:
        return self.state_valid and all(
            row.integrity_ok and row.foreign_keys_ok and row.schema_ok
            for row in checks
        )

    def fsync_tree(self, root: Path) -> None:
        self.fsync_calls += 1

    def publish_noreplace(self, staging: Path, final: Path) -> None:
        self.calls.append("publish-noreplace")
        if final.exists():
            raise FileExistsError(final)
        staging.rename(final)
        self.published = True

    def mask_stop_and_prove_idle(self, units):
        self.calls.append("mask-stop:" + ",".join(units))
        self.masked = True

    def remask_stop_and_prove_idle(self, units):
        self.calls.append("remask-stop:" + ",".join(units))
        self.masked = True

    def install_local_rollback(self, runtime_rpm: Path, app_rpm: Path, driver_rpm=None):
        self.calls.append(f"install:{runtime_rpm.name}")
        self.calls.append(f"install:{app_rpm.name}")
        if driver_rpm is not None:
            self.calls.append(f"install:{driver_rpm.name}")

    def driver_package_state_matches(self, contract):
        return not self.metadata_drift and self.nevras["lto-ltfs"] == contract["package_nevra"]

    def verify_untouched_driver(self, manifest) -> bool:
        self.calls.append("verify-driver")
        return True

    def verify_restored_ltfs_configuration(self, manifest) -> bool:
        self.calls.append("verify-ltfs-configuration")
        return True

    def create_recovery_directory(self, bundle_id: str) -> Path:
        directory = self.root / f"failed-new-{bundle_id}"
        directory.mkdir(mode=0o700)
        return directory

    def stage_snapshot(self, bundle: Path, snapshot) -> object:
        self.calls.append(f"stage:{snapshot.identity}")
        return f"staged:{snapshot.identity}"

    def swap_snapshot(self, identity: str, staged: object, recovery: Path) -> None:
        self.swap_calls.append(identity)
        if identity == self.fail_swap:
            raise RuntimeError("injected swap failure")

    def reverse_snapshot_swap(self, identity: str, recovery: Path) -> None:
        self.reverse_calls.append(identity)

    def restore_platform_state(self, manifest) -> None:
        self.calls.append("restore-platform")

    def restore_protected_catalog(self, manifest, recovery: Path) -> None:
        self.calls.append("restore-protected-catalog")

    def revalidate_restored_state(self, manifest) -> None:
        self.calls.append("revalidate-state")

    def activate_old_stack(self, manifest) -> None:
        self.calls.append("activate-old")
        self.masked = False

    def begin_restore_health_window(self, recovery: Path) -> None:
        self.calls.append("health-window-durable")

    def all_units_active(self, units) -> bool:
        return tuple(units) == self.module.STOP_UNITS

    def verify_old_health(self, manifest) -> bool:
        self.calls.append("verify-old-health")
        return self.old_health

    def keep_runtime_masked(self) -> None:
        self.calls.append("keep-masked")
        self.masked = True

    def append_restore_journal(self, recovery: Path, event: str) -> None:
        self.calls.append(f"journal:{event}")
        with (recovery / "restore.journal").open("a", encoding="utf-8") as handle:
            handle.write(event + "\n")
            handle.flush()
            os.fsync(handle.fileno())


class ArtifactProcessReferenceTests(unittest.TestCase):
    def setUp(self):
        self.module = _load_module()
        self.host = self.module.SystemRollbackHost()
        temporary = tempfile.TemporaryDirectory(prefix="artifact-reference-test-")
        self.addCleanup(temporary.cleanup)
        self.bundle = Path(temporary.name)
        self.payload = self.bundle / "catalog-copy.sqlite3"
        self.payload.write_bytes(b"x" * 4096)
        details = self.payload.stat()
        self.inodes = {(details.st_dev, details.st_ino)}
        self.task = Path(f"/proc/{os.getpid()}/task/{os.getpid()}")

    def check_task(self, task=None):
        self.assertTrue(hasattr(self.host, "_artifact_task_clear"), "real process-reference proof is missing")
        return self.host._artifact_task_clear(
            self.task if task is None else task, inodes=self.inodes, bundle=self.bundle,
        )

    def test_open_real_descriptor_blocks_artifact_pruning(self):
        with self.payload.open("rb"), self.assertRaisesRegex(self.module.RollbackError, "reference"):
            self.check_task()

    def test_unreferenced_local_tree_does_not_block_current_task(self):
        self.assertIsNone(self.check_task())

    def test_real_mapping_without_any_open_descriptor_blocks_artifact_pruning(self):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                              ctypes.c_int, ctypes.c_int, ctypes.c_long)
        libc.mmap.restype = ctypes.c_void_p
        libc.munmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
        descriptor = os.open(self.payload, os.O_RDONLY)
        try:
            address = libc.mmap(None, 4096, 1, 2, descriptor, 0)
            self.assertNotIn(address, (None, ctypes.c_void_p(-1).value))
        finally:
            os.close(descriptor)
        try:
            with self.assertRaisesRegex(self.module.RollbackError, "reference"):
                self.check_task()
        finally:
            self.assertEqual(0, libc.munmap(address, 4096))

    def test_incomplete_process_observation_is_not_an_empty_reference_set(self):
        task = self.bundle / "partial-task"
        task.mkdir()
        with self.assertRaises(self.module.RollbackError):
            self.check_task(task)

    def test_standalone_helper_loads_from_private_stage_under_sticky_tmp_only(self):
        scripts = self.bundle / "tools"
        scripts.mkdir(mode=0o700)
        helper = scripts / "deployment_artifacts.py"
        helper.write_bytes(b"class DeploymentArtifactRegistry:\n    qualified = True\n")
        helper.chmod(0o600)
        self.host._script_dir = scripts
        real_stat, real_fstat = os.stat, os.fstat

        def root_owned(result):
            values = list(result)
            values[4] = values[5] = 0
            return os.stat_result(values)

        with (mock.patch.object(self.module.os, "stat", side_effect=lambda *args, **kwargs: root_owned(real_stat(*args, **kwargs))),
              mock.patch.object(self.module.os, "fstat", side_effect=lambda *args: root_owned(real_fstat(*args)))):
            self.assertTrue(self.host._deployment_artifact_registry().qualified)
            self.host._artifact_registry = None
            scripts.chmod(0o777)
            with self.assertRaisesRegex(self.module.RollbackError, "authority"):
                self.host._deployment_artifact_registry()

    def test_copy_bundle_tools_retains_registry_when_original_stage_moves(self):
        scripts = self.bundle / "original-stage"
        scripts.mkdir()
        for name in ("rollback-rhel9.py", "deployment_artifacts.py", "verify-deployment-rhel9.py",
                     "rpm-verify-policy.json", "journal-policy.json"):
            (scripts / name).write_bytes(("qualified:" + name).encode())
        self.host._script_dir = self.host._deployment_dir = scripts
        copied = self.bundle / "bundle-tools"
        hashes = self.host.copy_bundle_tools(copied)
        scripts.rename(self.bundle / "stage-no-longer-at-original-path")
        self.assertIn("deployment_artifacts.py", hashes)
        self.assertEqual(_sha(b"qualified:deployment_artifacts.py"), hashes["deployment_artifacts.py"])
        self.assertEqual(b"qualified:deployment_artifacts.py", (copied / "deployment_artifacts.py").read_bytes())


class Rhel9RollbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = _load_module()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.rpm_dir = self.root / "rpms"
        self.rpm_dir.mkdir(mode=0o700)
        self.driver_contract = self.rpm_dir / "driver-input.json"
        driver = {
            "installed_file_metadata_sha256": "1" * 64,
            "package_nevra": "lto-ltfs-0.1.0-21.el9.x86_64",
            "rpm_header_sha256": "9" * 64,
            "rpm_payload_sha256": "a" * 64,
            "rpm_public_key_sha256": "4" * 64,
            "rpm_raw_sha256": _sha(b"driver-evidence-rpm"),
            "rpm_signing_policy_sha256": "6" * 64,
            "rpm_verify_policy_sha256": (
                "39c26ec18c7d8eadaad0c9b1b3d89fc133e5f60fb63f94ed427dbb8839fbadb0"
            ),
            "schema": 1,
            "source_provenance_evidence_sha256": "8" * 64,
            "source_provenance_status": "local-build-identity-only",
        }
        self.driver_bytes = (
            json.dumps(driver, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        self.driver_contract.write_bytes(self.driver_bytes)
        self.candidate_driver_contract = self.root / "candidate-driver-input.json"
        self.candidate_driver_bytes = self.driver_bytes
        self.candidate_driver_contract.write_bytes(self.candidate_driver_bytes)
        self.host = FakeRollbackHost(self.module, self.root)
        self._set_rpm_evidence()

    def test_new_bundle_requires_complete_ltfs_snapshot_closure(self):
        manifest = self._create()
        self.assertEqual(4, manifest.schema)
        self.assertEqual(
            (*SNAPSHOT_IDS, *LTFS_SNAPSHOT_PATHS),
            tuple(row.identity for row in manifest.snapshots),
        )
        value = self.module._manifest_value(manifest)
        for rows in (
            value["snapshots"][:-1],
            (*value["snapshots"], value["snapshots"][-1]),
            (*value["snapshots"], {**value["snapshots"][-1], "identity": "other"}),
        ):
            changed = {**value, "snapshots": rows}
            with self.subTest(rows=len(rows)), self.assertRaises(self.module.RollbackError):
                self.module._parse_manifest(changed, self.module._canonical(changed))
        legacy = {
            **value,
            "schema": 2,
            "snapshots": tuple(
                row for row in value["snapshots"] if row["identity"] in SNAPSHOT_IDS
            ),
        }
        legacy.pop("candidate_driver_input_sha256")
        parsed = self.module._parse_manifest(legacy, self.module._canonical(legacy))
        self.assertEqual(2, parsed.schema)
        self.assertEqual(SNAPSHOT_IDS, tuple(row.identity for row in parsed.snapshots))

    def test_release144_preserves_driver21_for_candidate_and_rollback(self):
        policy = json.loads((ROOT / "packaging/rpm/driver-rpm-verify-policy.json").read_text())
        policy["package_nevra"] = "lto-ltfs-0.1.0-21.el9.x86_64"
        self.candidate_driver_bytes = self.module._canonical({
            **json.loads(self.driver_bytes),
            "rpm_verify_policy_sha256": _sha(self.module._canonical(policy)),
        })
        self.candidate_driver_contract.write_bytes(self.candidate_driver_bytes)
        self.assertEqual(self.candidate_driver_bytes, self.module._validate_driver_contract(
            self.candidate_driver_contract, _sha(self.candidate_driver_bytes), candidate=True,
        ))
        self.assertEqual(self.driver_bytes, self.module._validate_driver_contract(
            self.driver_contract, _sha(self.driver_bytes),
        ))
        for path, data in (
            (self.driver_contract, self.driver_bytes),
            (self.candidate_driver_contract, self.candidate_driver_bytes),
        ):
            for candidate in (False, True):
                with self.subTest(path=path, candidate=candidate):
                    self.assertEqual(
                        data,
                        self.module._validate_driver_contract(
                            path, _sha(data), candidate=candidate
                        ),
                    )
        manifest = self._create()
        self.assertEqual(self.host.nevras, manifest.installed_nevras)
        self.assertEqual(manifest.driver_input_sha256, manifest.candidate_driver_input_sha256)

    def test_release144_recovery_is_closed_to_141_21_and_144_21_components(self):
        for application, driver, allowed in (
            (141, 21, True), (144, 21, True),
            (142, 21, False), (140, 21, False), (139, 21, False),
            (136, 21, False), (137, 21, False), (141, 20, False), (144, 20, False), (143, 21, False), (145, 21, False),
        ):
            state = {**self.host.nevras,
                     "lto-archiver": f"lto-archiver-0.11.27-{application}.el9.noarch",
                     "lto-ltfs": f"lto-ltfs-0.1.0-{driver}.el9.x86_64"}
            with self.subTest(application=application, driver=driver):
                self.assertEqual(allowed, self.module._coordinated_package_state_known(state))

    def test_release144_preserves_each_exact_driver_contract_for_its_role(self):
        for path, data, candidate in (
            (self.driver_contract, self.driver_bytes, False),
            (self.candidate_driver_contract, self.candidate_driver_bytes, True),
        ):
            with self.subTest(candidate=candidate):
                observed = self.module._validate_driver_contract(
                    path, _sha(data), candidate=candidate,
                )
                self.assertEqual(data, observed)
        self.assertEqual(self.candidate_driver_bytes, self.candidate_driver_contract.read_bytes())

    def test_release144_driver20_candidate_is_refused_before_publication(self):
        self.candidate_driver_bytes = self.module._canonical({
            **json.loads(self.driver_bytes),
            "package_nevra": "lto-ltfs-0.1.0-20.el9.x86_64",
            "rpm_raw_sha256": "f" * 64,
        })
        self.candidate_driver_contract.write_bytes(self.candidate_driver_bytes)
        with self.assertRaises(self.module.RollbackError):
            self._create()
        self.assertFalse(self.host.published)
        self.assertFalse(self.host.source_backup_prepared)

    def test_legacy_driver16_contract_remains_closed_to_legacy_bundles(self):
        legacy = self.module._canonical({
            **json.loads(self.driver_bytes),
            "package_nevra": "lto-ltfs-0.1.0-16.el9.x86_64",
            "rpm_verify_policy_sha256": "c00c446b14fdf8daa42094874cbe91ce2aa1f7ed5976a2c01c86eaff7fced4c5",
        })
        self.driver_contract.write_bytes(legacy)
        self.assertEqual(legacy, self.module._validate_driver_contract(
            self.driver_contract, _sha(legacy), legacy=True,
        ))
        for candidate in (False, True):
            with self.subTest(candidate=candidate), self.assertRaises(self.module.RollbackError):
                self.module._validate_driver_contract(
                    self.driver_contract, _sha(legacy), candidate=candidate,
                )

    def _rpm_inspector(self, *, output=None, exit_code=0, stderr="", legacy_driver_unsigned=False):
        host = self.module.SystemRollbackHost()
        host._require_tool = lambda _path: None

        def run(argv, *, accepted=(0,)):
            path = Path(argv[-1])
            if argv[0] == self.module._RPM:
                package = (
                    "lto-archiver-python-runtime" if "python-runtime" in path.name
                    else "lto-ltfs" if path.name.startswith("lto-ltfs-")
                    else "lto-archiver"
                )
                return subprocess.CompletedProcess(argv, 0,
                    f"{package}\n{path.stem}\n" + "a" * 64 + "\n", "")
            self.assertEqual(self.module._RPMKEYS, argv[0])
            if legacy_driver_unsigned and path.name == "lto-ltfs-0.1.0-16.el9.x86_64.rpm":
                stdout = (f"{path}:\n    Header SHA256 digest: OK\n"
                          "    Payload SHA256 digest: OK\n")
            elif output is not None:
                stdout = output.replace("{path}", str(path))
            elif "--verbose" in argv:
                stdout = (f"{path}:\n"
                    "    Header V4 RSA/SHA256 Signature, key ID a68e868d: OK\n"
                    "    Header SHA256 digest: OK\n"
                    "    Header SHA1 digest: OK\n"
                    "    Payload SHA256 digest: OK\n"
                    "    MD5 digest: OK\n")
            else:
                stdout = f"{path}: digests signatures OK\n"
            return subprocess.CompletedProcess(argv, exit_code, stdout, stderr)

        host._run = run
        return host

    def test_rpm_inspection_captures_verified_key_for_signed_driver17_restore(self):
        system = self._rpm_inspector()
        evidence = system.inspect_rollback_rpms(self.rpm_dir)
        self.assertEqual(3, len(evidence))
        self.assertEqual({("verified", "a68e868d")}, {
            (row.signature_status, row.signing_key_id) for row in evidence
        })
        driver = next(row for row in evidence if row.target == "driver-evidence")
        self.driver_bytes = self.module._canonical({
            **json.loads(self.driver_bytes), "rpm_header_sha256": driver.header_sha256,
        })
        self.driver_contract.write_bytes(self.driver_bytes)
        self.host.rpm_evidence = evidence
        manifest = self._create()
        system._verified_bundle = self.root / "rollback"
        system.captured_installed_package_state = self.host.captured_installed_package_state
        self.assertTrue(system.verify_rpm_evidence(manifest.rpms))
        self.assertTrue(system.verify_untouched_driver(manifest))

    def test_rpm_inspection_rejects_failed_missing_or_inconsistent_signatures(self):
        signed = ("{path}:\n"
                  "    Header V4 RSA/SHA256 Signature, key ID a68e868d: OK\n"
                  "    Header SHA256 digest: OK\n"
                  "    Payload SHA256 digest: OK\n")
        for output, code, error in (
            (signed, 1, ""), (signed, 0, "warning"),
            (signed.replace(": OK", ": NOKEY", 1), 0, ""),
            (signed.replace("RSA/SHA256", "RSA/SHA1"), 0, ""),
            (signed.replace("Payload SHA256 digest: OK", "Payload SHA256 digest: BAD"), 0, ""),
            (signed + "    V4 RSA/SHA256 Signature, key ID deadbeef: OK\n", 0, ""),
            ("{path}: digests signatures OK\n", 0, ""),
            ("{path}:\n    Header SHA256 digest: OK\n    Payload SHA256 digest: OK\n", 0, ""),
        ):
            with (
                self.subTest(output=output, code=code, error=error),
                self.assertRaises(self.module.RollbackError),
            ):
                self._rpm_inspector(output=output, exit_code=code, stderr=error).inspect_rollback_rpms(self.rpm_dir)

    def test_rpm_inspection_keeps_digest_only_driver16_legacy_evidence(self):
        directory = self.root / "legacy-rpms"
        directory.mkdir()
        (directory / "lto-ltfs-0.1.0-16.el9.x86_64.rpm").write_bytes(b"legacy")
        unsigned = ("{path}:\n    Header SHA256 digest: OK\n"
                    "    Header SHA1 digest: OK\n    Payload SHA256 digest: OK\n"
                    "    MD5 digest: OK\n")
        evidence = self._rpm_inspector(output=unsigned).inspect_rollback_rpms(directory)
        self.assertEqual(1, len(evidence))
        self.assertEqual(("legacy-unsigned", "absent"),
                         (evidence[0].signature_status, evidence[0].signing_key_id))

    def test_current_bundle_rejects_verified_rpm_with_absent_signing_key(self):
        self.host.rpm_evidence = tuple(
            replace(row, signing_key_id="absent") for row in self.host.rpm_evidence
        )
        with self.assertRaises(self.module.RollbackError):
            self._create()

    def test_legacy_bundle_rechecks_signed_rpms_with_historically_absent_key(self):
        manifest = self._create()
        bundle = self.root / "legacy-inspection"
        directory = bundle / "rpms"
        directory.mkdir(parents=True)
        nevras = {
            "lto-archiver": "lto-archiver-0.11.27-127.el9.noarch",
            "lto-archiver-python-runtime": "lto-archiver-python-runtime-0.11.27-3.el9.x86_64",
            "lto-ltfs": "lto-ltfs-0.1.0-16.el9.x86_64",
        }
        for nevra in nevras.values():
            (directory / (nevra + ".rpm")).write_bytes(nevra.encode())
        system = self._rpm_inspector(legacy_driver_unsigned=True)
        current = system.inspect_rollback_rpms(directory)
        historical = tuple(replace(row, signing_key_id="absent") for row in current)
        value = self.module._manifest_value(manifest)
        value.update(schema=2, installed_nevras=nevras,
                     rpms=[row.__dict__ for row in historical],
                     snapshots=[row for row in value["snapshots"] if row["identity"] in SNAPSHOT_IDS])
        value.pop("candidate_driver_input_sha256")
        (bundle / "bundle-manifest.json").write_bytes(self.module._canonical(value))
        system._verified_bundle = bundle
        self.assertTrue(system.verify_rpm_evidence(historical))
        changed = tuple(replace(row, sha256="f" * 64) if row.target == "application" else row
                        for row in historical)
        self.assertFalse(system.verify_rpm_evidence(changed))

    def _private_ltfs_snapshot_roots(self):
        roots = {
            name: self.root / "legacy" / name
            for name in self.module._SNAPSHOT_ROOTS
        }
        roots.update({
            name: self.root / "etc" / filename
            for name, filename in LTFS_SNAPSHOT_PATHS.items()
        })
        (self.root / "etc").mkdir(exist_ok=True)
        return roots

    def test_ltfs_file_snapshots_restore_bytes_metadata_absence_and_reverse(self):
        host = self.module.SystemRollbackHost()
        roots = self._private_ltfs_snapshot_roots()
        with (
            mock.patch.dict(self.module._SNAPSHOT_ROOTS, roots, clear=True),
            mock.patch.object(self.module.os, "chown"),
            mock.patch.object(host, "_stage_guard_is_secure", return_value=True),
        ):
            for identity in tuple(LTFS_SNAPSHOT_PATHS)[1:]:
                for present in (False, True):
                    with self.subTest(identity=identity, present=present):
                        target = roots[identity]
                        if present:
                            target.write_bytes(b"")
                            target.chmod(0o640)
                            os.setxattr(target, "user.ltfs-test", b"saved")
                        bundle = self.root / f"bundle-{identity}-{present}"
                        snapshot = host.copy_snapshot(
                            self.module.SnapshotSource(identity, 0),
                            bundle / "snapshots" / identity,
                        )
                        self.assertEqual(1 if present else 0, len(snapshot.files))
                        target.write_bytes(b"candidate configuration")
                        target.chmod(0o600)
                        staged = host.stage_snapshot(bundle, snapshot)
                        recovery = self.root / f"recovery-{identity}-{present}"
                        recovery.mkdir()
                        host.swap_snapshot(identity, staged, recovery)
                        self.assertEqual(present, target.exists())
                        if present:
                            self.assertEqual(b"", target.read_bytes())
                            self.assertEqual(0o640, stat.S_IMODE(target.stat().st_mode))
                            self.assertEqual(b"saved", os.getxattr(target, "user.ltfs-test"))
                        self.assertEqual(
                            b"candidate configuration",
                            (recovery / identity / target.name).read_bytes(),
                        )
                        host.reverse_snapshot_swap(identity, recovery)
                        self.assertEqual(b"candidate configuration", target.read_bytes())
                        target.unlink()

    def test_ltfs_snapshot_admission_rejects_broken_symlink_and_wrong_types(self):
        host = self.module.SystemRollbackHost()
        roots = self._private_ltfs_snapshot_roots()
        with mock.patch.dict(self.module._SNAPSHOT_ROOTS, roots, clear=True):
            for identity in LTFS_SNAPSHOT_PATHS:
                target = roots[identity]
                target.symlink_to(self.root / "missing")
                with self.subTest(identity=identity, kind="symlink"), self.assertRaises(self.module.RollbackError):
                    host.snapshot_sources()
                target.unlink()
                if identity == "ltfs_device_configuration":
                    target.write_bytes(b"wrong type")
                else:
                    target.mkdir()
                with self.subTest(identity=identity, kind="wrong type"), self.assertRaises(self.module.RollbackError):
                    host.snapshot_sources()
                if target.is_dir():
                    target.rmdir()
                else:
                    target.unlink()

    def test_ltfs_directory_snapshot_preserves_empty_absent_and_populated_states(self):
        host = self.module.SystemRollbackHost()
        identity = "ltfs_device_configuration"
        for state in ("absent", "empty", "populated"):
            with self.subTest(state=state):
                target = self.root / state / "lto-ltfs"
                target.parent.mkdir()
                if state != "absent":
                    target.mkdir(mode=0o750)
                    os.setxattr(target, "user.ltfs-test", b"directory")
                if state == "populated":
                    for name in ("device.json", "device.json.rpmnew", "device.json.rpmsave"):
                        (target / name).write_bytes(name.encode())
                        (target / name).chmod(0o640)
                bundle = self.root / f"directory-bundle-{state}"
                with (
                    mock.patch.dict(self.module._SNAPSHOT_ROOTS, {identity: target}),
                    mock.patch.object(self.module.os, "chown"),
                    mock.patch.object(host, "_stage_guard_is_secure", return_value=True),
                ):
                    snapshot = host.copy_snapshot(
                        self.module.SnapshotSource(identity, 0),
                        bundle / "snapshots" / identity,
                    )
                    target.mkdir(exist_ok=True)
                    (target / "candidate-only").write_bytes(b"new")
                    staged = host.stage_snapshot(bundle, snapshot)
                    recovery = self.root / f"directory-recovery-{state}"
                    recovery.mkdir()
                    host.swap_snapshot(identity, staged, recovery)
                    manifest = SimpleNamespace(snapshots=(snapshot,))
                    self.assertTrue(host.verify_restored_ltfs_configuration(manifest))
                    self.assertEqual(state != "absent", target.exists())
                    self.assertTrue((recovery / identity / "lto-ltfs" / "candidate-only").is_file())
                    target.mkdir(exist_ok=True)
                    (target / "drift").write_bytes(b"unexpected")
                    self.assertFalse(host.verify_restored_ltfs_configuration(manifest))

    def test_ltfs_configuration_is_verified_after_restore_and_before_activation(self):
        self._create()
        result = self.module.restore_bundle(self.root / "rollback", self.host)
        self.assertEqual("restored", result.status)
        calls = self.host.calls
        self.assertLess(calls.index("stage:ltfs_local_configuration_rpmsave"), calls.index("verify-ltfs-configuration"))
        self.assertLess(calls.index("verify-ltfs-configuration"), calls.index("verify-driver"))
        self.assertLess(calls.index("verify-driver"), calls.index("activate-old"))
        self.host = FakeRollbackHost(self.module, self.root)
        self._set_rpm_evidence()
        self._create("drifted-ltfs")
        self.host.verify_restored_ltfs_configuration = lambda _manifest: False
        result = self.module.restore_bundle(self.root / "drifted-ltfs", self.host)
        self.assertEqual("blocked", result.status)
        self.assertTrue(self.host.masked)
        self.assertNotIn("activate-old", self.host.calls)

    def test_schema2_restore_does_not_apply_ltfs_snapshots(self):
        manifest = self._create()
        bundle = self.root / "rollback"
        value = self.module._manifest_value(manifest)
        value["schema"] = 2
        value.pop("candidate_driver_input_sha256")
        value["installed_nevras"] = {
            "lto-archiver": "lto-archiver-0.11.27-127.el9.noarch",
            "lto-archiver-python-runtime": "lto-archiver-python-runtime-0.11.27-3.el9.x86_64",
            "lto-ltfs": "lto-ltfs-0.1.0-16.el9.x86_64",
        }
        for row in value["rpms"]:
            if row["target"] == "application":
                row["nevra"] = "lto-archiver-0.11.27-127.el9.noarch"
            elif row["target"] == "driver-evidence":
                row["nevra"] = "lto-ltfs-0.1.0-16.el9.x86_64"
                row["signature_status"] = "legacy-unsigned"
                row["signing_key_id"] = "absent"
            filename = row["nevra"] + ".rpm"
            if filename != row["filename"]:
                (bundle / "rpms" / row["filename"]).rename(bundle / "rpms" / filename)
                row["filename"] = filename
        driver_path = bundle / "contracts/driver-input.json"
        driver = {
            **json.loads(driver_path.read_bytes()),
            "package_nevra": "lto-ltfs-0.1.0-16.el9.x86_64",
            "rpm_verify_policy_sha256": "c00c446b14fdf8daa42094874cbe91ce2aa1f7ed5976a2c01c86eaff7fced4c5",
        }
        driver_path.write_bytes(self.module._canonical(driver))
        value["driver_input_sha256"] = _sha(driver_path.read_bytes())
        old_live_path = bundle / "contracts/old-live-contract.json"
        old_live = json.loads(old_live_path.read_bytes())
        old_live["installed_nevras"] = value["installed_nevras"]
        self.host.nevras = dict(value["installed_nevras"])
        old_live["installed_package_state"] = self.host.captured_installed_package_state()
        old_live["driver_authority"] = {
            key: driver[key] for key in old_live["driver_authority"]
        }
        self.host.nevras = {**self.host.nevras,
                            "lto-archiver": "lto-archiver-0.11.27-129.el9.noarch"}
        old_live_path.write_bytes(self.module._canonical(old_live))
        value["old_live_contract_sha256"] = _sha(old_live_path.read_bytes())
        value["snapshots"] = tuple(
            row for row in value["snapshots"] if row["identity"] in SNAPSHOT_IDS
        )
        (bundle / "bundle-manifest.json").write_bytes(self.module._canonical(value))
        (bundle / "rollback-SHA256SUMS").write_text(
            "\n".join(sorted(self.module._checksum_rows(bundle))) + "\n"
        )
        self.host.verify_restored_ltfs_configuration = mock.Mock(
            side_effect=AssertionError("legacy restore must not touch LTFS configuration")
        )
        result = self.module.restore_bundle(bundle, self.host)
        self.assertEqual("restored", result.status)
        self.assertEqual(list(SNAPSHOT_IDS), self.host.swap_calls)
        self.host.verify_restored_ltfs_configuration.assert_not_called()

    def test_ltfs_snapshot_verification_rejects_unrecorded_files_before_restore(self):
        host = self.module.SystemRollbackHost()
        identity = "ltfs_configuration_rpmnew"
        roots = self._private_ltfs_snapshot_roots()
        with mock.patch.dict(self.module._SNAPSHOT_ROOTS, roots, clear=True):
            for present in (False, True):
                with self.subTest(present=present):
                    target = roots[identity]
                    if present:
                        target.write_bytes(b"saved")
                    bundle = self.root / f"shape-{present}"
                    copied = bundle / "snapshots" / identity
                    snapshot = host.copy_snapshot(self.module.SnapshotSource(identity, 0), copied)
                    self.assertTrue(host.verify_snapshot_evidence(bundle, (snapshot,)))
                    (copied / "unrecorded").write_bytes(b"not in snapshot")
                    self.assertFalse(host.verify_snapshot_evidence(bundle, (snapshot,)))

    def test_ltfs_directory_snapshot_requires_recorded_root(self):
        host = self.module.SystemRollbackHost()
        identity = "ltfs_device_configuration"
        bundle = self.root / "shape-directory"
        copied = bundle / "snapshots" / identity
        copied.mkdir(parents=True)
        payload = copied / "device.json"
        payload.write_bytes(b"saved")
        snapshot = self.module.SnapshotEvidence(
            identity, 5, (host._file_evidence(payload, Path("device.json")),), ()
        )
        self.assertFalse(host.verify_snapshot_evidence(bundle, (snapshot,)))

    def test_dnf_authority_uses_regular_rhel9_entrypoint(self) -> None:
        self.assertEqual(Path("/usr/bin/dnf-3"), self.module._DNF)

    def test_coordinated_restore_binds_candidate_and_restores_driver(self):
        manifest = self._create()
        self.assertEqual(_sha(self.candidate_driver_bytes), manifest.candidate_driver_input_sha256)
        self.host.nevras = {
            **self.host.nevras,
            "lto-archiver": "lto-archiver-0.11.27-144.el9.noarch",
        }
        result = self.module.restore_bundle(self.root / "rollback", self.host)
        self.assertEqual("restored", result.status)
        self.assertIn("install:lto-ltfs-0.1.0-21.el9.x86_64.rpm", self.host.calls)

    def test_candidate_contract_tampering_or_unknown_driver_blocks_before_restore(self):
        self._create()
        bundle = self.root / "rollback"
        candidate = bundle / "contracts/candidate-driver-input.json"
        candidate.write_bytes(self.module._canonical({
            **json.loads(self.candidate_driver_bytes), "rpm_raw_sha256": "f" * 64,
        }))
        (bundle / "rollback-SHA256SUMS").write_text(
            "\n".join(sorted(self.module._checksum_rows(bundle))) + "\n")
        with self.assertRaises(self.module.RollbackError):
            self.module.restore_bundle(bundle, self.host)
        self.assertFalse(any(call.startswith("install:") for call in self.host.calls))

    def test_failed_driver_rollback_stays_masked_without_activation(self):
        self._create()
        self.host.install_local_rollback = mock.Mock(side_effect=self.module.RollbackError("DNF failed"))
        result = self.module.restore_bundle(self.root / "rollback", self.host)
        self.assertEqual("blocked", result.status)
        self.assertTrue(self.host.masked)
        self.assertNotIn("activate-old", self.host.calls)

    def test_driver_package_state_requires_successful_queries_and_exact_bytes(self):
        host = self.module.SystemRollbackHost()
        host._require_tool = lambda _path: None
        header = "lto-ltfs\nlto-ltfs-0.1.0-18.el9.x86_64\npayload\n"
        metadata = "package-owned metadata\n"
        contract = {"rpm_header_sha256": _sha(header.encode()),
                    "installed_file_metadata_sha256": _sha(metadata.encode())}
        for exit_code, stderr, expected in ((0, "", True), (1, "", False), (0, "warning", False)):
            with self.subTest(exit_code=exit_code, stderr=stderr):
                host._run = lambda argv, exit_code=exit_code, stderr=stderr: subprocess.CompletedProcess(
                    argv, exit_code, metadata if "-ql" in argv else header, stderr)
                self.assertEqual(expected, host.driver_package_state_matches(contract))

    def test_coordinated_rollback_admits_only_exact_known_package_combinations(self):
        host = self.module.SystemRollbackHost()
        host._require_tool = lambda _path: None
        runtime = self.root / "runtime.rpm"
        application = self.root / "application.rpm"
        driver = self.root / "driver.rpm"
        for path in (runtime, application, driver):
            path.write_bytes(b"fixture")
        predecessor = {
            "lto-archiver": "lto-archiver-0.11.27-141.el9.noarch",
            "lto-archiver-python-runtime": "lto-archiver-python-runtime-0.11.27-3.el9.x86_64",
            "lto-ltfs": "lto-ltfs-0.1.0-21.el9.x86_64",
        }
        for app_release, driver_release in ((141, 21), (144, 21)):
            state = {**predecessor,
                     "lto-archiver": f"lto-archiver-0.11.27-{app_release}.el9.noarch",
                     "lto-ltfs": f"lto-ltfs-0.1.0-{driver_release}.el9.x86_64"}
            commands = []
            host.installed_nevras = mock.Mock(side_effect=(state, predecessor))
            host._run = lambda argv, commands=commands: commands.append(argv)
            with self.subTest(app=app_release, driver=driver_release):
                host.install_local_rollback(runtime, application, driver)
                self.assertEqual(0 if state == predecessor else 1, len(commands))
                if commands:
                    self.assertEqual((runtime, application, driver), commands[0][-3:])
                    self.assertIn("--disablerepo=*", commands[0])
        commands = []
        host._run = lambda argv: commands.append(argv)
        for state in (
            {},
            {**predecessor, "lto-ltfs": "lto-ltfs-0.1.0-20.el9.x86_64"},
            {**predecessor, "lto-archiver": "lto-archiver-0.11.27-134.el9.noarch"},
        ):
            host.installed_nevras = lambda state=state: state
            with self.assertRaises(self.module.RollbackError):
                host.install_local_rollback(runtime, application, driver)
        self.assertEqual([], commands)

    def test_predecessor_without_reader_is_masked_without_persisting_absent_units(
        self,
    ) -> None:
        host = self.module.SystemRollbackHost()
        host._require_tool = lambda _path: None
        reader_units = {
            "lto-archiver-log-reader.socket",
            "lto-archiver-log-reader.service",
        }
        commands: list[tuple[str, ...]] = []

        def run(argv, accepted=(0,)):
            command = tuple(str(item) for item in argv)
            commands.append(command)
            if command[0] == str(self.module._FINDMNT):
                return subprocess.CompletedProcess(command, 1, "", "")
            if command[1] == "is-enabled":
                unit = command[-1]
                if unit in reader_units:
                    return subprocess.CompletedProcess(
                        command,
                        1,
                        "",
                        "Failed to get unit file state for "
                        f"{unit}: No such file or directory\n",
                    )
                state = (
                    "enabled"
                    if unit.endswith(".socket")
                    or unit == "lto-archiver-web.service"
                    else "static"
                )
                return subprocess.CompletedProcess(command, 0, f"{state}\n", "")
            if command[1] == "is-active":
                return subprocess.CompletedProcess(command, 3, "inactive\n", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        host._run = run
        with mock.patch.object(Path, "glob", return_value=()):
            host.mask_stop_and_prove_idle(self.module.STOP_UNITS)

        captured = dict(host.captured_enablement())
        self.assertEqual(set(self.module.STOP_UNITS) - reader_units, set(captured))
        self.assertNotIn("lto-archiver-log-reader.socket", captured)
        self.assertNotIn("lto-archiver-log-reader.service", captured)
        self.assertIn(
            ("/usr/bin/systemctl", "mask", "--runtime", *self.module.STOP_UNITS),
            commands,
        )
        self.assertEqual(
            set(self.module.STOP_UNITS),
            {command[-1] for command in commands if command[1] == "stop"},
        )

    def test_reader_transition_rejects_partial_or_unexpected_unit_absence(self):
        mismatched = subprocess.CompletedProcess(
            ("/usr/bin/systemctl",),
            1,
            "",
            "Failed to get unit file state for "
            "lto-archiver-log-reader.service: No such file or directory\n",
        )
        self.assertFalse(
            self.module._reader_unit_is_exactly_absent(
                mismatched, "lto-archiver-log-reader.socket"
            )
        )
        self.assertFalse(
            self.module._reader_unit_is_exactly_absent(
                mismatched, "lto-archiverd.service"
            )
        )
        for missing in (
            "lto-archiver-log-reader.socket",
            "lto-archiverd.service",
        ):
            with self.subTest(missing=missing):
                host = self.module.SystemRollbackHost()
                host._require_tool = lambda _path: None

                def run(argv, accepted=(0,)):
                    unit = str(argv[-1])
                    if unit == missing:
                        return subprocess.CompletedProcess(
                            argv, 1, "not-found\n", ""
                        )
                    state = (
                        "static"
                        if unit == "lto-archiver-log-reader.service"
                        else "enabled"
                    )
                    return subprocess.CompletedProcess(argv, 0, f"{state}\n", "")

                host._run = run
                with self.assertRaises(self.module.RollbackError):
                    host.captured_enablement()

    def test_rollback_restarts_only_units_owned_by_its_target(self) -> None:
        reader_socket = "lto-archiver-log-reader.socket"
        reader_service = "lto-archiver-log-reader.service"
        full_enablement = {
            unit: (
                "enabled"
                if unit.endswith(".socket") or unit == "lto-archiver-web.service"
                else "static"
            )
            for unit in self.module.STOP_UNITS
        }

        def activate(enablement):
            host = self.module.SystemRollbackHost()
            starts: list[str] = []
            enablement_updates: list[str] = []
            unmasked: list[str] = []

            def run(argv, accepted=(0,)):
                command = tuple(str(item) for item in argv)
                if command[1] == "unmask":
                    unmasked.extend(command[3:])
                elif command[1] in {"enable", "disable"}:
                    enablement_updates.append(command[-1])
                elif command[1] == "is-enabled":
                    state = enablement[command[-1]]
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        f"{state}\n",
                        "",
                    )
                elif command[1] == "start":
                    starts.append(command[-1])
                return subprocess.CompletedProcess(command, 0, "", "")

            host._run = run
            host.activate_old_stack(SimpleNamespace(unit_enablement=enablement))
            return starts, enablement_updates, unmasked

        predecessor = {
            unit: state
            for unit, state in full_enablement.items()
            if unit not in {reader_socket, reader_service}
        }
        predecessor_starts, predecessor_updates, predecessor_unmasked = activate(
            predecessor
        )
        self.assertEqual(set(self.module.STOP_UNITS), set(predecessor_unmasked))
        self.assertNotIn(reader_socket, predecessor_starts)
        self.assertNotIn(reader_service, predecessor_starts)
        self.assertNotIn(reader_socket, predecessor_updates)
        self.assertNotIn(reader_service, predecessor_updates)

        successor_starts, successor_updates, successor_unmasked = activate(
            full_enablement
        )
        self.assertEqual(set(self.module.STOP_UNITS), set(successor_unmasked))
        self.assertIn(reader_socket, successor_starts)
        self.assertNotIn(reader_service, successor_starts)
        self.assertIn(reader_socket, successor_updates)
        self.assertNotIn(reader_service, successor_updates)

    def test_rollback_maintenance_quiescence_accepts_only_safe_persisted_job_states(self):
        base = {
            "job": None,
            "operation": None,
            "admission_blocker": None,
            "critical_recovery": None,
        }
        self.assertTrue(self.module._daemon_quiescent_for_maintenance(base))
        for state in ("waiting_media", "paused"):
            with self.subTest(state=state):
                self.assertTrue(
                    self.module._daemon_quiescent_for_maintenance(
                        {**base, "job": {"state": state}}
                    )
                )
        for status in (
            {**base, "job": {"state": "writing"}},
            {**base, "job": {"state": "planned"}},
            {**base, "job": {}},
            {**base, "job": "waiting_media"},
            {**base, "operation": {"state": "running"}},
            {**base, "admission_blocker": {"state": "recovery_required"}},
            {**base, "critical_recovery": {"state": "required"}},
            {key: value for key, value in base.items() if key != "job"},
            {},
        ):
            with self.subTest(status=status):
                self.assertFalse(
                    self.module._daemon_quiescent_for_maintenance(status)
                )

    def test_basic_old_health_uses_safe_persisted_job_quiescence(self):
        base = {
            "accepting_mutations": True,
            "admission_blocker": None,
            "api_version": 1,
            "critical_recovery": None,
            "job": None,
            "operation": None,
        }

        class FakeSocket:
            def __init__(self, status) -> None:
                body = json.dumps(status, separators=(",", ":")).encode()
                self.chunks = [b"HTTP/1.1 200 OK\r\n\r\n" + body, b""]

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout):
                return None

            def connect(self, _path):
                return None

            def sendall(self, _request):
                return None

            def recv(self, _size):
                return self.chunks.pop(0)

        host = self.module.SystemRollbackHost()
        enablement = {
            unit: (
                "enabled"
                if unit.endswith(".socket") or unit == "lto-archiver-web.service"
                else "static"
            )
            for unit in self.module.STOP_UNITS
        }
        host._pre_mask_enablement = enablement

        def run(argv, accepted=(0,)):
            unit = str(argv[-1])
            return subprocess.CompletedProcess(
                argv,
                3 if unit == "lto-archiver-log-reader.service" else 0,
                "inactive\n"
                if unit == "lto-archiver-log-reader.service"
                else "active\n",
                "",
            )

        host._run = run
        manifest = SimpleNamespace(unit_enablement=enablement)
        self.assertTrue(host.all_units_active(self.module.STOP_UNITS))
        statuses = (
            (True, base),
            (True, {**base, "job": {"state": "paused"}}),
            (True, {**base, "job": {"state": "waiting_media"}}),
            (False, {**base, "job": {"state": "writing"}}),
            (False, {**base, "operation": {"state": "running"}}),
            (False, {**base, "admission_blocker": {"state": "blocked"}}),
            (False, {**base, "critical_recovery": {"state": "required"}}),
        )
        for expected, status in statuses:
            with (
                self.subTest(status=status),
                mock.patch.object(
                    self.module.socket,
                    "socket",
                    return_value=FakeSocket(status),
                ),
                mock.patch.object(
                    self.module,
                    "_predecessor_https_login_ok",
                    return_value=True,
                ),
            ):
                self.assertIs(
                    expected,
                    host._basic_old_health(manifest, {}),
                )

    def test_root_owned_restorecon_symlink_to_trusted_tool_is_accepted(self) -> None:
        host = self.module.SystemRollbackHost()
        restorecon = Path("/usr/sbin/restorecon")
        target = Path("/usr/sbin/setfiles")

        def trusted_stat(path, *, follow_symlinks=True):
            if path == restorecon and not follow_symlinks:
                return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
            if path == target and not follow_symlinks:
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
            if path in restorecon.parents or path in target.parents:
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
            raise AssertionError((path, follow_symlinks))

        with (
            mock.patch.object(Path, "stat", autospec=True, side_effect=trusted_stat),
            mock.patch.object(Path, "resolve", autospec=True, return_value=target),
        ):
            host._require_tool(restorecon)

    def test_restorecon_symlink_target_beneath_writable_ancestor_is_rejected(
        self,
    ) -> None:
        host = self.module.SystemRollbackHost()
        restorecon = Path("/usr/sbin/restorecon")
        target = Path("/opt/vendor/bin/setfiles")

        def untrusted_stat(path, *, follow_symlinks=True):
            if path == restorecon and not follow_symlinks:
                return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
            if path == restorecon and follow_symlinks:
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
            if path == Path("/opt/vendor") and not follow_symlinks:
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0)
            if path in restorecon.parents or path in target.parents:
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
            if path == target and not follow_symlinks:
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
            raise AssertionError((path, follow_symlinks))

        with (
            mock.patch.object(Path, "stat", autospec=True, side_effect=untrusted_stat),
            mock.patch.object(Path, "resolve", autospec=True, return_value=target),
            self.assertRaises(self.module.RollbackError),
        ):
            host._require_tool(restorecon)

    def test_restorecon_symlink_to_writable_target_is_rejected(self) -> None:
        host = self.module.SystemRollbackHost()
        restorecon = Path("/usr/sbin/restorecon")
        target = Path("/usr/sbin/setfiles")

        def untrusted_stat(path, *, follow_symlinks=True):
            if path == restorecon and not follow_symlinks:
                return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
            if path == target and not follow_symlinks:
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o777, st_uid=0)
            if path in restorecon.parents or path in target.parents:
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
            raise AssertionError((path, follow_symlinks))

        with (
            mock.patch.object(Path, "stat", autospec=True, side_effect=untrusted_stat),
            mock.patch.object(Path, "resolve", autospec=True, return_value=target),
            self.assertRaises(self.module.RollbackError),
        ):
            host._require_tool(restorecon)

    def test_rollback_package_install_is_idempotent_and_closed(self) -> None:
        host = self.module.SystemRollbackHost()
        runtime = self.root / "lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm"
        application = self.root / "lto-archiver-0.11.27-127.el9.noarch.rpm"
        runtime.write_bytes(b"runtime")
        application.write_bytes(b"application")
        predecessor = {
            "lto-archiver": "lto-archiver-0.11.27-127.el9.noarch",
            "lto-archiver-python-runtime": (
                "lto-archiver-python-runtime-0.11.27-3.el9.x86_64"
            ),
            "lto-ltfs": "lto-ltfs-0.1.0-16.el9.x86_64",
        }
        deployed = {
            **predecessor,
            "lto-archiver": "lto-archiver-0.11.27-129.el9.noarch",
        }
        self.assertEqual(predecessor, self.module._LEGACY_PREDECESSOR_NEVRAS)
        host._require_tool = mock.Mock()
        host._run = mock.Mock()
        host.installed_nevras = mock.Mock(return_value=predecessor)

        host.install_local_rollback(runtime, application)

        host._run.assert_not_called()

        host.installed_nevras = mock.Mock(side_effect=(deployed, predecessor))
        host.install_local_rollback(runtime, application)
        self.assertEqual(self.module._DNF, Path(host._run.call_args.args[0][0]))

        host._run.reset_mock()
        host.installed_nevras = mock.Mock(return_value={})
        with self.assertRaises(self.module.RollbackError):
            host.install_local_rollback(runtime, application)
        host._run.assert_not_called()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_predecessor_https_probe_requires_exact_login_surface(self):
        self.assertTrue(
            hasattr(self.module, "_predecessor_https_login_ok")
        )

        class Response:
            status = 200

            def __init__(
                self,
                *,
                url: str = "https://console.example.invalid:8443/login",
                content_type: str = "text/html; charset=utf-8",
                cache_control: str = "no-store",
                body: bytes = b'<html><form action="/login"></form></html>',
            ) -> None:
                self.url = url
                self.headers = {
                    "Content-Type": content_type,
                    "Cache-Control": cache_control,
                }
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit: int) -> bytes:
                return self.body

            def geturl(self) -> str:
                return self.url

        probe = {
            "url": "https://console.example.invalid:8443/login",
            "ca_certificate": "/var/lib/lto-archiver-web/tls/server.crt",
        }
        with mock.patch.object(
            self.module.ssl, "create_default_context", return_value=object()
        ):
            for response, expected in (
                (Response(), True),
                (Response(url="https://console.example.invalid:8443/"), False),
                (Response(content_type="application/json"), False),
                (Response(cache_control="public"), False),
                (Response(body=b"<html>not the login form</html>"), False),
            ):
                with self.subTest(response=response), mock.patch.object(
                    self.module.urllib.request,
                    "urlopen",
                    return_value=response,
                ):
                    self.assertEqual(
                        expected,
                        self.module._predecessor_https_login_ok(probe),
                    )

    def _set_rpm_evidence(self, *, extra: bool = False, app_nevra: str | None = None):
        rows = []
        definitions = (
            (
                "application",
                "lto-archiver-0.11.27-141.el9.noarch",
                "lto-archiver-0.11.27-141.el9.noarch.rpm",
            ),
            (
                "runtime",
                "lto-archiver-python-runtime-0.11.27-3.el9.x86_64",
                "lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm",
            ),
            (
                "driver-evidence",
                "lto-ltfs-0.1.0-21.el9.x86_64",
                "lto-ltfs-0.1.0-21.el9.x86_64.rpm",
            ),
        )
        for target, nevra, filename in definitions:
            if target == "application" and app_nevra is not None:
                nevra = app_nevra
            data = (target + "-rpm").encode()
            (self.rpm_dir / filename).write_bytes(data)
            rows.append(
                self.module.RpmEvidence(
                    target=target,
                    filename=filename,
                    nevra=nevra,
                    sha256=_sha(data),
                    size=len(data),
                    signature_status="verified",
                    signing_key_id="0123456789abcdef",
                    header_sha256="9" * 64,
                    payload_sha256="a" * 64,
                )
            )
        if extra:
            rows.append(
                self.module.RpmEvidence(
                    "extra",
                    "lto-archiver-extra.rpm",
                    "lto-archiver-extra-1.noarch",
                    "b" * 64,
                    1,
                    "legacy-unsigned",
                    "absent",
                    "c" * 64,
                    "d" * 64,
                )
            )
        self.host.rpm_evidence = tuple(rows)

    def _request(self, name: str = "rollback"):
        return self.module.CreateBundleRequest(
            bundle_dir=self.root / name,
            rollback_rpm_dir=self.rpm_dir,
            expected_custom_web_unit_sha256=self.host.custom_hash,
            driver_input_contract=self.driver_contract,
            expected_driver_input_sha256=_sha(self.driver_bytes),
            candidate_driver_input_contract=self.candidate_driver_contract,
            expected_candidate_driver_input_sha256=_sha(self.candidate_driver_bytes),
            predecessor_web_probe={
                "url": "https://console.example.invalid:8443/login",
                "ca_certificate": str(self.driver_contract),
            },
        )

    def _create(self, name: str = "rollback"):
        return self.module.create_bundle(self._request(name), self.host)

    def test_create_requires_root_new_0700_home_backed_bundle_and_exact_old_rpm_closure(self):
        self.host.root_user = False
        with self.assertRaises(self.module.RollbackError):
            self._create("not-root")
        self.host.root_user = True
        self.host.secure_parent = False
        with self.assertRaises(self.module.RollbackError):
            self._create("bad-parent")
        self.host.secure_parent = True
        existing = self.root / "existing"
        existing.mkdir()
        with self.assertRaises(self.module.RollbackError):
            self._create("existing")
        self._set_rpm_evidence(extra=True)
        with self.assertRaises(self.module.RollbackError):
            self._create("extra-rpm")
        self._set_rpm_evidence(
            app_nevra="lto-archiver-0.11.27-99.el9.noarch"
        )
        with self.assertRaises(self.module.RollbackError):
            self._create("wrong-rpm")
        self._set_rpm_evidence()
        self.host.rollback_rpm_authority = False
        with self.assertRaises(self.module.RollbackError):
            self._create("untrusted-rpm-directory")

    def test_system_host_requires_root_0700_rpm_directory_and_root_safe_regular_rpms(self):
        host = self.module.SystemRollbackHost()
        directory = Path("/root/rollback-rpms")
        filenames = ("app.rpm", "runtime.rpm", "driver.rpm")
        directory_stat = type("Stat", (), {"st_mode": stat.S_IFDIR | 0o700, "st_uid": 0})()
        safe_file_stat = type(
            "Stat",
            (),
            {"st_mode": stat.S_IFREG | 0o600, "st_uid": 0, "st_nlink": 1},
        )()
        with (
            mock.patch.object(self.module.os, "open", side_effect=(10, 11, 12, 13)),
            mock.patch.object(
                self.module.os,
                "fstat",
                side_effect=(directory_stat, safe_file_stat, safe_file_stat, safe_file_stat),
            ),
            mock.patch.object(self.module.os, "close"),
        ):
            self.assertTrue(host.rollback_rpm_authority_ok(directory, filenames))

        for unsafe_directory in (
            type("Stat", (), {"st_mode": stat.S_IFDIR | 0o755, "st_uid": 0})(),
            type("Stat", (), {"st_mode": stat.S_IFDIR | 0o700, "st_uid": 1000})(),
        ):
            with self.subTest(unsafe_directory=unsafe_directory), mock.patch.object(
                self.module.os, "open", return_value=10
            ), mock.patch.object(
                self.module.os, "fstat", return_value=unsafe_directory
            ), mock.patch.object(self.module.os, "close"):
                self.assertFalse(
                    host.rollback_rpm_authority_ok(directory, filenames)
                )

        for unsafe_file in (
            type("Stat", (), {"st_mode": stat.S_IFREG | 0o622, "st_uid": 0, "st_nlink": 1})(),
            type("Stat", (), {"st_mode": stat.S_IFLNK | 0o600, "st_uid": 0, "st_nlink": 1})(),
            type("Stat", (), {"st_mode": stat.S_IFREG | 0o600, "st_uid": 1000, "st_nlink": 1})(),
            type("Stat", (), {"st_mode": stat.S_IFREG | 0o600, "st_uid": 0, "st_nlink": 2})(),
        ):
            with self.subTest(unsafe_file=unsafe_file), mock.patch.object(
                self.module.os, "open", side_effect=(10, 11, 12, 13)
            ), mock.patch.object(
                self.module.os,
                "fstat",
                side_effect=(
                    directory_stat,
                    unsafe_file,
                    safe_file_stat,
                    safe_file_stat,
                ),
            ), mock.patch.object(self.module.os, "close"):
                self.assertFalse(
                    host.rollback_rpm_authority_ok(directory, filenames)
                )
        with mock.patch.object(
            self.module.os, "open", side_effect=OSError("symlink refused")
        ):
            self.assertFalse(
                host.rollback_rpm_authority_ok(directory, filenames)
            )

    def test_release_rollback_uses_sibling_policy_authorities(self) -> None:
        deploy = self.root / "release/DEPLOY"
        deploy.mkdir(parents=True)
        script = deploy / "rollback-rhel9.py"
        script.write_text("# authority fixture\n")
        for name in ("rpm-verify-policy.json", "journal-policy.json"):
            (deploy / name).write_text("{}\n")

        with mock.patch.object(self.module, "__file__", str(script)):
            host = self.module.SystemRollbackHost()

        self.assertEqual(deploy, host._script_dir)
        self.assertEqual(deploy, host._deployment_dir)

    def test_bundle_security_allows_preserved_metadata_only_below_snapshots(self) -> None:
        host = self.module.SystemRollbackHost()
        bundle = self.root / "bundle"
        snapshots = bundle / "snapshots"
        preserved = snapshots / "application_state/catalog.db"
        contract = bundle / "contracts/deployment.json"

        root_directory = type(
            "Stat", (), {"st_mode": stat.S_IFDIR | 0o700, "st_uid": 0}
        )()
        service_file = type(
            "Stat", (), {"st_mode": stat.S_IFREG | 0o660, "st_uid": 994}
        )()
        root_writable_file = type(
            "Stat", (), {"st_mode": stat.S_IFREG | 0o660, "st_uid": 0}
        )()
        preserved_symlink = type(
            "Stat", (), {"st_mode": stat.S_IFLNK | 0o777, "st_uid": 994}
        )()

        self.assertTrue(
            host._bundle_security_entry_ok(bundle, bundle, root_directory)
        )
        self.assertTrue(
            host._bundle_security_entry_ok(bundle, snapshots, root_directory)
        )
        self.assertTrue(
            host._bundle_security_entry_ok(bundle, preserved, service_file)
        )
        self.assertFalse(
            host._bundle_security_entry_ok(bundle, contract, service_file)
        )
        self.assertFalse(
            host._bundle_security_entry_ok(bundle, contract, root_writable_file)
        )
        self.assertFalse(
            host._bundle_security_entry_ok(bundle, preserved, preserved_symlink)
        )

    def test_staged_tree_reapplies_owners_and_verifies_before_swap(self) -> None:
        host = self.module.SystemRollbackHost()
        source = self.root / "snapshot"
        staged = self.root / "staged"
        source.mkdir(mode=0o750)
        staged.mkdir(mode=0o700)
        source_file = source / "catalog.db"
        staged_file = staged / "catalog.db"
        source_file.write_bytes(b"catalog")
        staged_file.write_bytes(b"catalog")
        source_file.chmod(0o640)
        staged_file.chmod(0o640)
        file_evidence = host._file_evidence(source_file, Path("catalog.db"))
        directory_evidence = host._directory_evidence(source, Path("."))
        file_evidence = self.module.FileEvidence(
            **{
                **file_evidence.__dict__,
                "uid": 1234,
                "gid": 2345,
            }
        )
        directory_evidence = self.module.DirectoryEvidence(
            **{
                **directory_evidence.__dict__,
                "uid": 3456,
                "gid": 4567,
            }
        )
        snapshot = self.module.SnapshotEvidence(
            "application_state", 7, (file_evidence,), (directory_evidence,)
        )

        with mock.patch.object(self.module.os, "chown") as chown:
            host._apply_staged_tree_metadata(
                source, staged, snapshot, Path(".")
            )

        self.assertEqual(
            [
                mock.call(staged_file, 1234, 2345, follow_symlinks=False),
                mock.call(staged, 3456, 4567, follow_symlinks=False),
            ],
            chown.call_args_list,
        )

        actual_snapshot = self.module.SnapshotEvidence(
            "application_state",
            7,
            (host._file_evidence(staged_file, Path("catalog.db")),),
            (host._directory_evidence(staged, Path(".")),),
        )
        self.assertTrue(
            host._verify_staged_tree(staged, actual_snapshot, Path("."))
        )
        staged_file.write_bytes(b"corrupt")
        self.assertFalse(
            host._verify_staged_tree(staged, actual_snapshot, Path("."))
        )

    def test_stage_snapshot_refuses_unverified_staged_tree(self) -> None:
        host = self.module.SystemRollbackHost()
        bundle = self.root / "bundle"
        source = bundle / "snapshots/application_state"
        target = self.root / "live/application-state"
        source.mkdir(parents=True)
        target.parent.mkdir(parents=True)
        payload = source / "catalog.db"
        payload.write_bytes(b"catalog")
        snapshot = self.module.SnapshotEvidence(
            "application_state",
            7,
            (host._file_evidence(payload, Path("catalog.db")),),
            (host._directory_evidence(source, Path(".")),),
        )
        original = self.module._SNAPSHOT_ROOTS["application_state"]
        self.module._SNAPSHOT_ROOTS["application_state"] = target
        try:
            with (
                mock.patch.object(self.module.os, "chown"),
                mock.patch.object(host, "_stage_guard_is_secure", return_value=True),
                mock.patch.object(
                    host, "_verify_staged_tree", return_value=False
                ) as verify,
            ):
                with self.assertRaises(self.module.RollbackError):
                    host.stage_snapshot(bundle, snapshot)
        finally:
            self.module._SNAPSHOT_ROOTS["application_state"] = original

        verify.assert_called_once()
        self.assertEqual(
            [], list(target.parent.glob(".application-state.restore-*"))
        )

    def test_stage_snapshot_keeps_service_owned_tree_below_root_guard(self) -> None:
        host = self.module.SystemRollbackHost()
        bundle = self.root / "bundle"
        source = bundle / "snapshots/application_state"
        target = self.root / "live/application-state"
        source.mkdir(parents=True)
        target.parent.mkdir(parents=True)
        payload = source / "catalog.db"
        payload.write_bytes(b"authorized")
        snapshot = self.module.SnapshotEvidence(
            "application_state",
            10,
            (host._file_evidence(payload, Path("catalog.db")),),
            (host._directory_evidence(source, Path(".")),),
        )
        original = self.module._SNAPSHOT_ROOTS["application_state"]
        self.module._SNAPSHOT_ROOTS["application_state"] = target
        try:
            with (
                mock.patch.object(self.module.os, "chown") as chown,
                mock.patch.object(host, "_stage_guard_is_secure", return_value=True),
            ):
                staged = host.stage_snapshot(bundle, snapshot)
        finally:
            self.module._SNAPSHOT_ROOTS["application_state"] = original

        self.assertEqual(1, len(staged.guard_directories))
        guard = staged.guard_directories[0]
        replacement = staged.items[0][1]
        self.assertIsNotNone(replacement)
        self.assertEqual(guard, replacement.parent)
        self.assertNotEqual(target.parent, replacement.parent)
        self.assertEqual(0o700, stat.S_IMODE(guard.stat().st_mode))
        self.assertIn(mock.call(guard, 0, 0), chown.call_args_list)

    def test_sqlite_validation_uses_isolated_copy_without_source_sidecars(self) -> None:
        host = self.module.SystemRollbackHost()
        catalog = self.root / "catalog.db"
        connection = sqlite3.connect(catalog)
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)")
        connection.execute(
            "INSERT INTO metadata(key,value) VALUES('schema_version','37')"
        )
        connection.commit()
        connection.close()
        with mock.patch.object(
            self.module.tempfile,
            "TemporaryDirectory",
            wraps=tempfile.TemporaryDirectory,
        ) as temporary:
            self.assertTrue(
                host._sqlite_check(catalog, catalog=True, catalog_schema="37")
            )

        temporary.assert_called_once_with(prefix="lto-rollback-sqlite-")
        self.assertFalse(catalog.with_name("catalog.db-wal").exists())

    def _protected_validation_fixture(self, *, schema="40", invalid_fk=False):
        path = self.root / "20260912T220000000000Z-abcdef123456-p-v40-0123456789abcdef.sqlite3"
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)")
            connection.execute("INSERT INTO metadata VALUES('schema_version',?)", (schema,))
            connection.execute("CREATE TABLE parent(id INTEGER PRIMARY KEY, payload BLOB)")
            connection.execute("INSERT INTO parent VALUES(1,zeroblob(1048576))")
            if invalid_fk:
                connection.execute("CREATE TABLE child(id INTEGER REFERENCES parent(id))")
                connection.execute("INSERT INTO child VALUES(99)")
        path.chmod(0o600)
        return path

    def test_protected_validation_needs_only_one_catalog_sized_scratch_copy(self):
        path = self._protected_validation_fixture()
        source_hash = _sha(path.read_bytes())
        scratch = self.root / "scratch"
        scratch.mkdir(mode=0o700)
        real_temporary = tempfile.TemporaryDirectory
        real_connect = sqlite3.connect
        observed_bytes = []

        def connect(*args, **kwargs):
            observed_bytes.append(sum(item.stat().st_size for item in scratch.rglob('*') if item.is_file()))
            return real_connect(*args, **kwargs)

        with (
            mock.patch.object(self.module, "_ROOT_UID", os.geteuid()),
            mock.patch.object(self.module, "_ROOT_GID", os.getegid()),
            mock.patch.object(self.module.tempfile, "TemporaryDirectory", side_effect=lambda **kw: real_temporary(dir=scratch, **kw)),
            mock.patch.object(self.module.sqlite3, "connect", side_effect=connect),
        ):
            self.assertEqual((40, source_hash), self.module.SystemRollbackHost()._protected_source_values(path))
        self.assertGreater(max(observed_bytes), 0)
        self.assertLessEqual(max(observed_bytes), path.stat().st_size)
        self.assertEqual(source_hash, _sha(path.read_bytes()))
        self.assertEqual([], list(scratch.iterdir()))

    def test_protected_validation_still_rejects_foreign_key_violation(self):
        path = self._protected_validation_fixture(invalid_fk=True)
        with (
            mock.patch.object(self.module, "_ROOT_UID", os.geteuid()),
            mock.patch.object(self.module, "_ROOT_GID", os.getegid()),
        ):
            self.assertIsNone(self.module.SystemRollbackHost()._protected_source_values(path))

    def test_protected_validation_still_rejects_wrong_schema(self):
        path = self._protected_validation_fixture(schema="39")
        with (
            mock.patch.object(self.module, "_ROOT_UID", os.geteuid()),
            mock.patch.object(self.module, "_ROOT_GID", os.getegid()),
        ):
            self.assertIsNone(self.module.SystemRollbackHost()._protected_source_values(path))

    def test_stage_guard_cleanup_covers_creation_and_pre_swap_failures(self) -> None:
        host = self.module.SystemRollbackHost()
        parent = self.root / "guards"
        parent.mkdir()
        with mock.patch.object(
            self.module.os, "chown", side_effect=OSError("injected chown failure")
        ):
            with self.assertRaises(self.module.RollbackError):
                host._new_stage_guard(parent, ".restore-")
        self.assertEqual([], list(parent.iterdir()))

        guard = parent / ".restore-drifted"
        guard.mkdir(mode=0o700)
        staged = self.module.StagedSwap((), (guard,))
        recovery = self.root / "recovery"
        recovery.mkdir()
        with mock.patch.object(host, "_stage_guard_is_secure", return_value=False):
            with self.assertRaises(self.module.RollbackError):
                host.swap_snapshot("application_state", staged, recovery)
        self.assertFalse(guard.exists())

    def test_capacity_requires_snapshot_plus_rpms_plus_max_twenty_percent_or_ten_gib(self):
        subtotal = (
            sum(self.host.snapshot_bytes.values())
            + sum(row.size for row in self.host.rpm_evidence)
            + len(b"sqlite-backup-schema-40")
        )
        expected = subtotal + max((subtotal + 4) // 5, 10 * 1024**3)
        self.host.available = expected - 1
        with self.assertRaises(self.module.RollbackError):
            self._create("too-small")
        self.host.available = expected
        manifest = self._create("exact-capacity")
        self.assertEqual(expected, manifest.required_capacity_bytes)
        self.assertEqual(expected, manifest.available_capacity_bytes)

    def test_create_quiescently_copies_all_state_tls_custom_unit_and_dropins_with_metadata(self):
        manifest = self._create()
        self.assertEqual(
            set(SNAPSHOT_IDS) | set(LTFS_SNAPSHOT_PATHS),
            {row.identity for row in manifest.snapshots},
        )
        self.assertTrue(
            all(row.files and row.files[0].mode == 0o600 for row in manifest.snapshots)
        )

        source = self.root / "metadata-source"
        empty = source / "empty-private"
        empty.mkdir(parents=True, mode=0o700)
        source.chmod(0o710)
        destination = self.root / "metadata-copy"
        original = self.module._SNAPSHOT_ROOTS["configuration"]
        self.module._SNAPSHOT_ROOTS["configuration"] = source
        try:
            copied = self.module.SystemRollbackHost().copy_snapshot(
                self.module.SnapshotSource("configuration", 0), destination
            )
        finally:
            self.module._SNAPSHOT_ROOTS["configuration"] = original
        self.assertEqual({".", "empty-private"}, {
            row.relative_path for row in copied.directories
        })
        self.assertEqual(0o710, stat.S_IMODE(destination.stat().st_mode))
        self.assertEqual(
            0o700, stat.S_IMODE((destination / "empty-private").stat().st_mode)
        )
        os.setxattr(empty, "user.rollback-test", b"authority")
        degraded_destination = self.root / "metadata-degraded-copy"
        real_copystat = self.module.shutil.copystat

        def omit_directory_xattr(source_path, target_path, **kwargs):
            real_copystat(source_path, target_path, **kwargs)
            if Path(source_path) == empty:
                os.removexattr(target_path, "user.rollback-test")

        self.module._SNAPSHOT_ROOTS["configuration"] = source
        try:
            with mock.patch.object(
                self.module.shutil,
                "copystat",
                side_effect=omit_directory_xattr,
            ), self.assertRaises(self.module.RollbackError):
                self.module.SystemRollbackHost().copy_snapshot(
                    self.module.SnapshotSource("configuration", 0),
                    degraded_destination,
                )
        finally:
            self.module._SNAPSHOT_ROOTS["configuration"] = original
        self.assertEqual(
            set(SNAPSHOT_IDS) | set(LTFS_SNAPSHOT_PATHS),
            {call.split(":", 1)[1] for call in self.host.calls if call.startswith("copy:")},
        )
        serialized = (self.root / "rollback" / "bundle-manifest.json").read_text()
        self.assertNotIn("secret-", serialized)
        self.assertNotIn("private-machine-id", serialized)

    def test_create_checks_catalog_broker_share_auth_and_protected_backup_copies_read_only(self):
        manifest = self._create()
        self.assertEqual(
            set(self.module.REQUIRED_STATE_CHECKS),
            {row.identity for row in manifest.state_checks},
        )
        self.assertEqual(1, self.host.calls.count("state-checks-read-only"))
        self.assertLess(
            self.host.calls.index("prepare-source-backup"),
            self.host.calls.index("copy:application_state"),
        )
        self.assertFalse(
            any(name in self.host.calls for name in ("mount", "recover", "write-db"))
        )
        self.assertEqual(4, manifest.schema)
        self.assertEqual(40, manifest.source_catalog_schema)
        self.assertEqual(_sha(self.host.source_catalog_bytes), manifest.source_catalog_sha256)
        selected = self.root / "rollback" / manifest.protected_backup_relative_path
        self.assertTrue(selected.is_file())
        self.assertEqual(_sha(selected.read_bytes()), manifest.protected_backup_sha256)
        self.assertTrue(manifest.protected_backup_relative_path.startswith("release-recovery/"))

    def test_bundle_rejects_selected_backup_tamper_even_when_outer_checksums_are_rewritten(self):
        manifest = self._create("selected-tamper")
        bundle = self.root / "selected-tamper"
        selected = bundle / manifest.protected_backup_relative_path
        selected.write_bytes(b"different but plausible sqlite bytes")
        (bundle / "rollback-SHA256SUMS").write_text(
            "\n".join(sorted(self.module._checksum_rows(bundle))) + "\n",
            encoding="ascii",
        )

        with self.assertRaisesRegex(
            self.module.RollbackError, "protected source"
        ):
            self.module.verify_bundle(bundle, self.host)

    def test_bundle_rejects_noncanonical_protected_backup_relative_paths(self):
        canonical_name = (
            "20260831T120000000000Z-abcdef123456-p-v40-"
            "0123456789abcdef.sqlite3"
        )
        variants = (
            f"release-recovery//{canonical_name}",
            f"release-recovery/./{canonical_name}",
            f"release-recovery/{canonical_name}/",
            f"release-recovery\\{canonical_name}",
            f"/release-recovery/{canonical_name}",
            "release-recovery/%2e%2e",
        )
        host = self.module.SystemRollbackHost()
        for relative in variants:
            with self.subTest(relative=relative):
                manifest = SimpleNamespace(
                    protected_backup_relative_path=relative,
                    protected_backup_sha256="b" * 64,
                    source_catalog_schema=40,
                    source_catalog_sha256="a" * 64,
                    snapshots=(
                        SimpleNamespace(
                            identity="application_state",
                            files=(
                                SimpleNamespace(
                                    relative_path="catalog.db",
                                    sha256="a" * 64,
                                ),
                            ),
                        ),
                    ),
                )
                with mock.patch.object(
                    host,
                    "_protected_source_values",
                    return_value=(40, "b" * 64),
                ):
                    self.assertFalse(
                        host.verify_protected_source(self.root, manifest)
                    )

    def test_bundle_publication_is_no_replace_fsynced_and_self_verified(self):
        self._create()
        bundle = self.root / "rollback"
        self.assertTrue(self.host.published)
        self.assertGreaterEqual(self.host.fsync_calls, 1)
        checksums = (bundle / "rollback-SHA256SUMS").read_text().splitlines()
        self.assertEqual(checksums, sorted(checksums))
        self.assertEqual(
            self.module.verify_bundle(bundle, self.host).bundle_id,
            json.loads((bundle / "bundle-manifest.json").read_text())["bundle_id"],
        )
        with self.assertRaises(self.module.RollbackError):
            self._create()

        cli_bundle = self.root / "cli-bundle"
        cli_output = self.root / "cli-result.json"
        with mock.patch.object(
            self.module, "SystemRollbackHost", return_value=self.host
        ):
            return_code = self.module.main(
                [
                    "create",
                    "--bundle-dir",
                    str(cli_bundle),
                    "--rollback-rpm-dir",
                    str(self.rpm_dir),
                    "--expected-custom-web-unit-sha256",
                    self.host.custom_hash,
                    "--driver-input-contract",
                    str(self.driver_contract),
                    "--expected-driver-input-sha256",
                    _sha(self.driver_bytes),
                    "--candidate-driver-input-contract",
                    str(self.candidate_driver_contract),
                    "--expected-candidate-driver-input-sha256",
                    _sha(self.candidate_driver_bytes),
                    "--predecessor-https-login-url",
                    "https://console.example.invalid:8443/login",
                    "--predecessor-https-ca-certificate",
                    str(self.driver_contract),
                    "--firewall-zone",
                    "public",
                    "--json-output",
                    str(cli_output),
                ]
            )
        self.assertEqual(0, return_code)
        self.assertEqual("created", json.loads(cli_output.read_text())["status"])

    def test_verify_rejects_host_nevra_hash_signature_mode_owner_database_or_manifest_drift(self):
        scenarios = (
            "host",
            "nevra",
            "hash",
            "signature",
            "security",
            "database",
            "metadata",
            "manifest",
        )
        for index, scenario in enumerate(scenarios):
            with self.subTest(scenario=scenario):
                name = f"verify-{index}"
                self._set_rpm_evidence()
                self._create(name)
                bundle = self.root / name
                if scenario == "host":
                    self.host.binding = b"different-host"
                elif scenario == "nevra":
                    self.host.nevras = dict(self.host.nevras)
                    self.host.nevras["lto-archiver"] = "wrong"
                elif scenario == "hash":
                    (bundle / "snapshots/configuration/payload.bin").write_bytes(b"drift")
                elif scenario == "signature":
                    self.host.rpm_valid = False
                elif scenario == "security":
                    self.host.bundle_secure = False
                elif scenario == "database":
                    self.host.state_valid = False
                elif scenario == "metadata":
                    self.host.metadata_drift = True
                else:
                    (bundle / "bundle-manifest.json").write_text("{}\n")
                with self.assertRaises(self.module.RollbackError):
                    self.module.verify_bundle(bundle, self.host)
                self.host = FakeRollbackHost(self.module, self.root)

    def test_restore_stages_and_swaps_exact_roots_without_merge_or_silent_deletion(self):
        manifest = self._create()
        self.host.nevras = {
            "lto-archiver": "lto-archiver-0.11.27-144.el9.noarch",
            "lto-archiver-python-runtime": (
                "lto-archiver-python-runtime-0.11.27-3.el9.x86_64"
            ),
            "lto-ltfs": "lto-ltfs-0.1.0-21.el9.x86_64",
        }
        result = self.module.restore_bundle(self.root / "rollback", self.host)
        self.assertEqual("restored", result.status)
        self.assertEqual(
            [row.identity for row in manifest.snapshots], self.host.swap_calls
        )
        self.assertFalse(any("merge" in call for call in self.host.calls))
        self.assertLess(
            self.host.calls.index("restore-protected-catalog"),
            self.host.calls.index("revalidate-state"),
        )

        system = self.module.SystemRollbackHost()
        bundle = self.root / "rollback"
        system._verified_bundle = bundle
        state = json.loads(
            (bundle / "contracts/old-live-contract.json").read_text()
        )["installed_package_state"]
        system.captured_installed_package_state = lambda: state
        system.inspect_rollback_rpms = lambda _directory: manifest.rpms
        self.assertTrue(system.verify_untouched_driver(manifest))
        unsigned = replace(manifest, rpms=tuple(
            replace(row, signature_status="legacy-unsigned", signing_key_id="absent")
            if row.target == "driver-evidence" else row for row in manifest.rpms
        ))
        system.inspect_rollback_rpms = lambda _directory: unsigned.rpms
        self.assertFalse(system.verify_untouched_driver(unsigned))
        system.inspect_rollback_rpms = lambda _directory: manifest.rpms
        drifted = json.loads(json.dumps(state))
        drifted["packages"]["lto-ltfs"][
            "installed_file_metadata_sha256"
        ] = "0" * 64
        system.captured_installed_package_state = lambda: drifted
        self.assertFalse(system.verify_untouched_driver(manifest))
        for field, value in (
            ("rpm_verify_exit", 0),
            ("rpm_verify_stdout_sha256", _sha(b"")),
            ("rpm_verify_rows", []),
        ):
            with self.subTest(field=field):
                changed = json.loads(json.dumps(state))
                changed["packages"]["lto-ltfs"][field] = value
                system.captured_installed_package_state = lambda changed=changed: changed
                self.assertFalse(system.verify_untouched_driver(manifest))

        activation_calls: list[tuple[tuple[str, ...], tuple[int, ...]]] = []

        def activation_run(argv, accepted=(0,)):
            command = tuple(str(item) for item in argv)
            activation_calls.append((command, accepted))
            if command[1] == "is-enabled":
                state = manifest.unit_enablement[command[-1]]
                return subprocess.CompletedProcess(
                    command,
                    1 if state == "disabled" else 0,
                    f"{state}\n",
                    "",
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        system._run = activation_run
        system.activate_old_stack(manifest)
        self.assertTrue(
            all(
                accepted == (0,)
                for command, accepted in activation_calls
                if "enable" in command or "disable" in command
            )
        )
        self.assertFalse(
            any(
                ("enable" in command or "disable" in command)
                and command[1] in {"enable", "disable"}
                and command[-1].endswith(".service")
                and command[-1] != "lto-archiver-web.service"
                for command, _accepted in activation_calls
            )
        )

        for returncode, stdout, expected in (
            (0, "enabled\n", "enabled"),
            (1, "disabled\n", "disabled"),
            (0, "static\n", "static"),
        ):
            result = subprocess.CompletedProcess(
                ("/usr/bin/systemctl",), returncode, stdout, ""
            )
            self.assertEqual(
                expected, self.module._canonical_unit_enablement(result)
            )
        for returncode, stdout, stderr in (
            (4, "not-found\n", ""),
            (1, "not-found\n", ""),
            (0, "enabled-runtime\n", ""),
            (0, "enabled\n", "warning"),
        ):
            with self.subTest(returncode=returncode, stdout=stdout):
                with self.assertRaises(self.module.RollbackError):
                    self.module._canonical_unit_enablement(
                        subprocess.CompletedProcess(
                            ("/usr/bin/systemctl",),
                            returncode,
                            stdout,
                            stderr,
                        )
                    )
        capture_enablement = self.module.SystemRollbackHost()
        capture_enablement._require_tool = lambda _path: None
        capture_enablement._run = (
            lambda argv, accepted=(0,): subprocess.CompletedProcess(
                tuple(str(item) for item in argv), 4, "not-found\n", ""
            )
        )
        with self.assertRaises(self.module.RollbackError):
            capture_enablement.captured_enablement()

        self.assertTrue(
            self.module._legacy_rpm_rows_expected_only(
                "lto-archiver",
                ["S.5....T.  c /etc/lto-archiver/config.toml"],
            )
        )
        self.assertTrue(
            self.module._legacy_rpm_rows_expected_only(
                "lto-ltfs",
                ["S.5....T.  c /etc/lto-ltfs/device.json"],
            )
        )
        for package, rows in (
            ("lto-archiver", ["....L....  c /etc/lto-archiver/config.toml"]),
            ("lto-archiver", ["S.5....T.  c /usr/bin/lto-archiver"]),
            ("lto-archiver-python-runtime", ["S........    /usr/lib/runtime"]),
            ("lto-ltfs", []),
            ("lto-ltfs", ["S.5....T.  c /etc/lto-ltfs/other.json"]),
            ("lto-ltfs", ["S........    /usr/bin/ltfs"]),
        ):
            with self.subTest(package=package, rows=rows):
                self.assertFalse(
                    self.module._legacy_rpm_rows_expected_only(package, rows)
                )

        exact_driver = subprocess.CompletedProcess(
            ("/usr/bin/rpm", "-V", "lto-ltfs"),
            1,
            "S.5....T.  c /etc/lto-ltfs/device.json\n",
            "",
        )
        self.assertTrue(
            self.module._legacy_rpm_verification_expected_only(
                "lto-ltfs", exact_driver
            )
        )
        self.assertTrue(
            self.module._legacy_rpm_verification_expected_only(
                "lto-archiver",
                subprocess.CompletedProcess(
                    exact_driver.args,
                    1,
                    "S.5....T.  c /etc/lto-archiver/config.toml\n",
                    "",
                ),
            )
        )
        self.assertTrue(
            self.module._legacy_rpm_verification_expected_only(
                "lto-archiver-python-runtime",
                subprocess.CompletedProcess(exact_driver.args, 0, "", ""),
            )
        )
        for package, result in (
            (
                "lto-ltfs",
                subprocess.CompletedProcess(
                    exact_driver.args, 0, exact_driver.stdout, ""
                ),
            ),
            (
                "lto-ltfs",
                subprocess.CompletedProcess(
                    exact_driver.args,
                    1,
                    exact_driver.stdout.rstrip("\n"),
                    "",
                ),
            ),
            (
                "lto-archiver-python-runtime",
                subprocess.CompletedProcess(exact_driver.args, 1, "", ""),
            ),
            (
                "lto-archiver",
                subprocess.CompletedProcess(
                    exact_driver.args,
                    1,
                    "S.5....T.  c /etc/lto-archiver/config.toml",
                    "",
                ),
            ),
        ):
            with self.subTest(package=package, result=result):
                self.assertFalse(
                    self.module._legacy_rpm_verification_expected_only(
                        package, result
                    )
                )

        capture = self.module.SystemRollbackHost()
        capture._require_tool = lambda _path: None
        capture.installed_nevras = lambda: {
            "lto-archiver": "lto-archiver-0.11.27-100.el9.noarch"
        }

        def inconsistent_capture(argv, accepted=(0,)):
            command = tuple(str(item) for item in argv)
            if "-ql" in command:
                return subprocess.CompletedProcess(
                    command, 0, "metadata\n", ""
                )
            return subprocess.CompletedProcess(command, 1, "", "")

        capture._run = inconsistent_capture
        with self.assertRaises(self.module.RollbackError):
            capture.captured_installed_package_state()

    def test_predecessor_catalog_schema40_requires_an_exact_protected_backup(self) -> None:
        catalog = self.root / "predecessor-catalog.db"
        connection = sqlite3.connect(catalog)
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)")
        connection.execute(
            "INSERT INTO metadata(key,value) VALUES('schema_version','40')"
        )
        connection.commit()
        connection.close()
        host = self.module.SystemRollbackHost()

        self.assertTrue(host._sqlite_check(catalog, catalog=True))
        connection = sqlite3.connect(catalog)
        connection.execute(
            "UPDATE metadata SET value='39' WHERE key='schema_version'"
        )
        connection.commit()
        connection.close()
        self.assertFalse(host._sqlite_check(catalog, catalog=True))

        snapshots = self.root / "snapshots"
        (snapshots / "application_state/backups").mkdir(parents=True)
        with (
            mock.patch.object(host, "_sqlite_check", return_value=True),
            mock.patch.object(host, "_share_state_check", return_value=True),
        ):
            checks = {
                row.identity: row for row in host.check_copied_state(snapshots)
            }

        self.assertFalse(checks["protected_catalog_backup"].integrity_ok)
        self.assertFalse(checks["protected_catalog_backup"].foreign_keys_ok)
        self.assertFalse(checks["protected_catalog_backup"].schema_ok)

    def test_catalog_validation_survives_checkpoint_between_database_and_wal_copy(self) -> None:
        """A raw DB/WAL pair from different generations must not reject healthy state."""
        path = self.root / "growing-catalog.db"
        writer = sqlite3.connect(path)
        self.addCleanup(writer.close)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)")
        writer.execute("INSERT INTO metadata VALUES('schema_version','40')")
        writer.execute("CREATE TABLE payload(id INTEGER PRIMARY KEY,value BLOB)")
        writer.commit()
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        real_copy = self.module.shutil.copyfile

        def checkpoint_after_main_copy(source, destination, *args, **kwargs):
            result = real_copy(source, destination, *args, **kwargs)
            if Path(source) == path:
                writer.executemany(
                    "INSERT INTO payload(value) VALUES(?)", [(b"x" * 4096,)] * 100
                )
                writer.commit()
                writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                writer.execute("INSERT INTO payload(value) VALUES(?)", (b"y" * 4096,))
                writer.commit()
            return result

        with mock.patch.object(self.module.shutil, "copyfile", side_effect=checkpoint_after_main_copy):
            valid = self.module.SystemRollbackHost()._sqlite_check(path, catalog=True)
        self.assertEqual(writer.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
        self.assertTrue(valid, "Concurrent checkpoints must not create a torn validation copy")

    def test_validation_snapshot_handles_commits_during_incremental_backup(self) -> None:
        path = self.root / "concurrent-backup.db"
        writer = sqlite3.connect(path)
        self.addCleanup(writer.close)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)")
        writer.execute("INSERT INTO metadata VALUES('schema_version','40')")
        writer.execute("CREATE TABLE payload(value BLOB)")
        writer.executemany("INSERT INTO payload VALUES(?)", [(b"x" * 4096,)] * 50)
        writer.commit()
        changed = []
        real_connect = sqlite3.connect

        class InterleavedConnection(sqlite3.Connection):
            def backup(self, target, *, pages=-1, progress=None, sleep=0.05):
                def advance(status, remaining, total):
                    if remaining > 0 and not changed:
                        writer.execute("INSERT INTO payload VALUES(?)", (b"y" * 4096,))
                        writer.commit()
                        writer.execute("PRAGMA wal_checkpoint(PASSIVE)")
                        changed.append(True)
                    if progress is not None:
                        progress(status, remaining, total)

                return super().backup(target, pages=1, progress=advance, sleep=sleep)

        def connect(database, *args, **kwargs):
            if str(database) == path.as_uri() + "?mode=ro":
                kwargs["factory"] = InterleavedConnection
            return real_connect(database, *args, **kwargs)

        with mock.patch.object(self.module.sqlite3, "connect", side_effect=connect):
            self.assertTrue(self.module.SystemRollbackHost()._sqlite_check(path, catalog=True))
        self.assertEqual(writer.execute("SELECT COUNT(*) FROM payload").fetchone(), (51,))
        self.assertEqual(writer.execute("PRAGMA integrity_check").fetchall(), [("ok",)])

    def test_validation_snapshot_includes_wal_without_changing_source(self) -> None:
        path = self.root / "catalog #with?reserved.db"
        writer = sqlite3.connect(path)
        self.addCleanup(writer.close)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)")
        writer.execute("INSERT INTO metadata VALUES('schema_version','39')")
        writer.commit()
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        writer.execute("UPDATE metadata SET value='40'")
        writer.commit()
        wal = path.with_name(path.name + "-wal")
        before = (path.read_bytes(), wal.read_bytes())
        self.assertTrue(self.module.SystemRollbackHost()._sqlite_check(path, catalog=True))
        self.assertEqual((path.read_bytes(), wal.read_bytes()), before)

    def test_validation_snapshot_rejects_symlinked_shared_memory(self) -> None:
        path = self.root / "unsafe-sidecar.db"
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)")
        connection.execute("INSERT INTO metadata VALUES('schema_version','40')")
        connection.commit()
        connection.close()
        unrelated = self.root / "unrelated"
        unrelated.write_bytes(b"do not modify")
        path.with_name(path.name + "-shm").symlink_to(unrelated)
        self.assertFalse(self.module.SystemRollbackHost()._sqlite_check(path, catalog=True))
        self.assertEqual(unrelated.read_bytes(), b"do not modify")

    def test_validation_snapshot_deadline_refuses_without_changing_source(self) -> None:
        path = self.root / "deadline.db"
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)")
        connection.execute("INSERT INTO metadata VALUES('schema_version','40')")
        connection.commit()
        connection.close()
        before = path.read_bytes()
        with mock.patch.object(self.module.time, "monotonic", side_effect=[0.0, 301.0]):
            self.assertFalse(self.module.SystemRollbackHost()._sqlite_check(path, catalog=True))
        self.assertEqual(path.read_bytes(), before)

    def test_deployment_quiescence_rejects_unsafe_catalog_work(self) -> None:
        host = self.module.SystemRollbackHost()

        def catalog_with(
            name: str,
            *,
            jobs: tuple[str, ...] = (),
            operations: tuple[str, ...] = (),
        ) -> Path:
            path = self.root / f"deployment-{name}.db"
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)")
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES('schema_version','40')"
            )
            connection.execute("CREATE TABLE automatic_jobs(id TEXT PRIMARY KEY,status TEXT)")
            connection.execute("CREATE TABLE daemon_operations(id TEXT PRIMARY KEY,state TEXT)")
            connection.executemany(
                "INSERT INTO automatic_jobs(id,status) VALUES(?,?)",
                ((f"job-{index}", state) for index, state in enumerate(jobs, 1)),
            )
            connection.executemany(
                "INSERT INTO daemon_operations(id,state) VALUES(?,?)",
                ((f"op-{index}", state) for index, state in enumerate(operations, 1)),
            )
            connection.commit()
            connection.close()
            return path

        for name, jobs in (
            ("none", ()),
            ("paused", ("paused",)),
            ("waiting", ("waiting_media",)),
        ):
            with self.subTest(name=name):
                self.assertTrue(
                    host._sqlite_check(
                        catalog_with(name, jobs=jobs),
                        catalog=True,
                        deployment_quiescent=True,
                    )
                )

        unsafe = (
            ("writing", ("writing",), ()),
            ("planned", ("planned",), ()),
            ("multiple", ("paused", "waiting_media"), ()),
            ("running-operation", ("waiting_media",), ("running",)),
            ("recovery-operation", ("paused",), ("recovery_required",)),
        )
        for name, jobs, operations in unsafe:
            with self.subTest(name=name):
                path = catalog_with(name, jobs=jobs, operations=operations)
                self.assertFalse(
                    host._sqlite_check(
                        path,
                        catalog=True,
                        deployment_quiescent=True,
                    )
                )
                self.assertTrue(host._sqlite_check(path, catalog=True))

    def test_stopped_schema40_catalog_creates_a_canonical_atomic_backup(self) -> None:
        catalog = self.root / "catalog.db"
        connection = sqlite3.connect(catalog)
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)")
        connection.execute(
            "INSERT INTO metadata(key,value) VALUES('schema_version','40')"
        )
        connection.commit()
        connection.close()
        catalog.chmod(0o600)
        host = self.module.SystemRollbackHost()
        connect = sqlite3.connect

        def secure_connect(database, *args, **kwargs):
            if isinstance(database, Path):
                self.assertTrue(database.exists())
                self.assertEqual(0o600, stat.S_IMODE(database.stat().st_mode))
                self.assertFalse(database.is_symlink())
            return connect(database, *args, **kwargs)

        with (
            mock.patch.object(self.module, "_LIVE_CATALOG", catalog, create=True),
            mock.patch.object(self.module, "_ROOT_UID", os.geteuid(), create=True),
            mock.patch.object(self.module, "_ROOT_GID", os.getegid(), create=True),
            mock.patch.object(
                self.module.sqlite3, "connect", side_effect=secure_connect
            ),
        ):
            prepared = host.prepare_source_catalog_backup(self.root)

        self.assertRegex(prepared.path.name, self.module._PROTECTED_BACKUP_NAME)
        self.assertEqual(0o600, stat.S_IMODE(prepared.path.stat().st_mode))
        with (
            mock.patch.object(self.module, "_LIVE_CATALOG", catalog, create=True),
            mock.patch.object(self.module, "_ROOT_UID", os.geteuid(), create=True),
            mock.patch.object(self.module, "_ROOT_GID", os.getegid(), create=True),
        ):
            self.assertTrue(host.validate_prepared_source(prepared))
        self.assertEqual([], list(prepared.path.parent.glob(".*.tmp-*")))

    def test_restore_replaces_catalog_from_selected_backup_and_quarantines_sidecars(self) -> None:
        bundle = self.root / "restore-source #bundle"
        selected_root = bundle / "release-recovery"
        selected_root.mkdir(parents=True, mode=0o700)
        selected = selected_root / (
            "20260831T120000000000Z-abcdef123456-p-v40-"
            "0123456789abcdef.sqlite3"
        )
        connection = sqlite3.connect(selected)
        self.assertEqual(
            ("wal",), connection.execute("PRAGMA journal_mode=WAL").fetchone()
        )
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)")
        connection.execute(
            "INSERT INTO metadata VALUES('schema_version','40')"
        )
        connection.commit()
        connection.close()
        selected.chmod(0o600)
        source_sha256 = _sha(selected.read_bytes())
        self.assertFalse(selected.with_name(selected.name + "-wal").exists())
        self.assertFalse(selected.with_name(selected.name + "-shm").exists())
        live_root = self.root / "live-application"
        live_root.mkdir()
        live = live_root / "catalog.db"
        live.write_bytes(b"successor catalog")
        live.chmod(0o600)
        for suffix in ("-wal", "-shm"):
            live.with_name(live.name + suffix).write_bytes(b"stale")
        recovery = self.root / "restore-recovery"
        recovery.mkdir()
        host = self.module.SystemRollbackHost()
        host._verified_bundle = bundle
        manifest = SimpleNamespace(
            protected_backup_relative_path=selected.relative_to(bundle).as_posix(),
            protected_backup_sha256=_sha(selected.read_bytes()),
            source_catalog_schema=40,
            source_catalog_sha256="a" * 64,
        )

        with (
            mock.patch.object(self.module, "_LIVE_CATALOG", live, create=True),
            mock.patch.object(self.module, "_ROOT_UID", os.geteuid(), create=True),
            mock.patch.object(self.module, "_ROOT_GID", os.getegid(), create=True),
        ):
            host.restore_protected_catalog(manifest, recovery)

        connection = sqlite3.connect(live)
        self.assertEqual(
            ("40",),
            connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone(),
        )
        connection.close()
        self.assertEqual(source_sha256, _sha(selected.read_bytes()))
        self.assertFalse(selected.with_name(selected.name + "-wal").exists())
        self.assertFalse(selected.with_name(selected.name + "-shm").exists())
        self.assertFalse(live.with_name(live.name + "-wal").exists())
        self.assertFalse(live.with_name(live.name + "-shm").exists())
        self.assertEqual(
            {"catalog.db-wal", "catalog.db-shm"},
            {path.name for path in (recovery / "catalog-sidecars").iterdir()},
        )

        selected_root.chmod(0o755)
        insecure_recovery = self.root / "insecure-source-recovery"
        insecure_recovery.mkdir()
        with (
            mock.patch.object(self.module, "_LIVE_CATALOG", live, create=True),
            mock.patch.object(self.module, "_ROOT_UID", os.geteuid(), create=True),
            mock.patch.object(self.module, "_ROOT_GID", os.getegid(), create=True),
            self.assertRaisesRegex(
                self.module.RollbackError, "selected protected source"
            ),
        ):
            host.restore_protected_catalog(manifest, insecure_recovery)

    def test_schema40_service_backups_allow_older_while_release_source_is_separate(
        self,
    ) -> None:
        snapshots = self.root / "source-bound-snapshots"
        backup_root = snapshots / "application_state/backups"
        backup_root.mkdir(parents=True)
        backup_root.chmod(0o750)
        catalog = snapshots / "application_state/catalog.db"

        def write_catalog(path: Path, schema: str) -> None:
            connection = sqlite3.connect(path)
            connection.execute(
                "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)"
            )
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES('schema_version',?)",
                (schema,),
            )
            connection.commit()
            connection.close()
            if path.parent == backup_root:
                path.chmod(0o600)

        write_catalog(catalog, "40")
        older = backup_root / (
            "20260830T120000000000Z-abcdef123456-p-v34-"
            "0123456789abcdef.sqlite3"
        )
        write_catalog(older, "34")
        host = self.module.SystemRollbackHost()

        with (
            mock.patch.object(host, "_share_state_check", return_value=True),
            mock.patch.object(
                host,
                "_sqlite_check",
                wraps=host._sqlite_check,
            ),
        ):
            only_older = {
                row.identity: row for row in host.check_copied_state(snapshots)
            }
        self.assertTrue(only_older["protected_catalog_backup"].schema_ok)

        exact = backup_root / (
            "20260830T120000000001Z-abcdef123456-p-v40-"
            "0123456789abcdef.sqlite3"
        )
        write_catalog(exact, "40")
        with mock.patch.object(host, "_share_state_check", return_value=True):
            with_exact = {
                row.identity: row for row in host.check_copied_state(snapshots)
            }
        self.assertTrue(with_exact["protected_catalog_backup"].schema_ok)

        future = backup_root / (
            "20260830T120000000002Z-abcdef123456-p-v41-"
            "0123456789abcdef.sqlite3"
        )
        write_catalog(future, "41")
        with mock.patch.object(host, "_share_state_check", return_value=True):
            with_future = {
                row.identity: row for row in host.check_copied_state(snapshots)
            }
        self.assertFalse(with_future["protected_catalog_backup"].schema_ok)
        future.unlink()

        exact.unlink()
        write_catalog(exact, "38")
        with mock.patch.object(host, "_share_state_check", return_value=True):
            mismatched = {
                row.identity: row for row in host.check_copied_state(snapshots)
            }
        self.assertFalse(mismatched["protected_catalog_backup"].schema_ok)

    def test_schema40_backup_gate_rejects_foreign_key_damage(self) -> None:
        snapshots = self.root / "dirty-source-snapshots"
        backup_root = snapshots / "application_state/backups"
        backup_root.mkdir(parents=True)
        catalog = snapshots / "application_state/catalog.db"
        backup = backup_root / (
            "20260830T120000000000Z-abcdef123456-p-v40-"
            "0123456789abcdef.sqlite3"
        )
        for path in (catalog, backup):
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT);
                INSERT INTO metadata VALUES('schema_version','40');
                CREATE TABLE parent(id INTEGER PRIMARY KEY);
                CREATE TABLE child(parent_id INTEGER REFERENCES parent(id));
                INSERT INTO child VALUES(7);
                """
            )
            connection.commit()
            connection.close()
        host = self.module.SystemRollbackHost()
        with mock.patch.object(host, "_share_state_check", return_value=True):
            checks = {
                row.identity: row for row in host.check_copied_state(snapshots)
            }
        self.assertFalse(checks["protected_catalog_backup"].foreign_keys_ok)

    def test_copied_state_rejects_invalid_protected_backup_from_application_layout(
        self,
    ) -> None:
        snapshots = self.root / "snapshots"
        backup_root = snapshots / "application_state/backups"
        backup_root.mkdir(parents=True)
        (backup_root / "catalog-schema-34-p-invalid.sqlite3").write_bytes(
            b"not-sqlite"
        )

        checks = {
            row.identity: row
            for row in self.module.SystemRollbackHost().check_copied_state(
                snapshots
            )
        }

        self.assertFalse(checks["protected_catalog_backup"].integrity_ok)
        self.assertFalse(checks["protected_catalog_backup"].foreign_keys_ok)
        self.assertFalse(checks["protected_catalog_backup"].schema_ok)

    def test_protected_backups_match_canonical_filename_schema_and_range(
        self,
    ) -> None:
        cases = (
            (
                "20260830T120000000000Z-abcdef123456-p-v13-"
                "0123456789abcdef.sqlite3",
                "13",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v34-"
                "0123456789abcdef.sqlite3",
                "34",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v33-"
                "0123456789abcdef.sqlite3",
                "34",
                False,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v12-"
                "0123456789abcdef.sqlite3",
                "12",
                False,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v35-"
                "0123456789abcdef.sqlite3",
                "35",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-o-v35-"
                "0123456789abcdef.sqlite3",
                "35",
                False,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v36-"
                "0123456789abcdef.sqlite3",
                "36",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v37-"
                "0123456789abcdef.sqlite3",
                "37",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v38-"
                "0123456789abcdef.sqlite3",
                "38",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v39-"
                "0123456789abcdef.sqlite3",
                "39",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v40-"
                "0123456789abcdef.sqlite3",
                "40",
                True,
            ),
            (
                "20260830T120000000000Z-abcdef123456-p-v41-"
                "0123456789abcdef.sqlite3",
                "41",
                False,
            ),
            ("invalid-p-v34-name.sqlite3", "34", False),
        )
        host = self.module.SystemRollbackHost()
        for index, (filename, schema, expected) in enumerate(cases):
            with self.subTest(filename=filename, schema=schema):
                snapshots = self.root / f"snapshots-{index}"
                backup_root = snapshots / "application_state/backups"
                backup_root.mkdir(parents=True)
                backup_root.chmod(0o750)
                connection = sqlite3.connect(backup_root / filename)
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)"
                )
                connection.execute(
                    "INSERT INTO metadata(key,value) VALUES('schema_version',?)",
                    (schema,),
                )
                connection.commit()
                connection.close()
                (backup_root / filename).chmod(0o600)
                self.assertEqual(
                    expected, host._protected_backup_check(backup_root / filename)
                )

    def test_service_backup_validator_rejects_insecure_mode_owner_and_hardlinks(self) -> None:
        backup_root = self.root / "service-backups"
        backup_root.mkdir(mode=0o750)
        backup = backup_root / (
            "20260831T120000000000Z-abcdef123456-p-v35-"
            "0123456789abcdef.sqlite3"
        )
        connection = sqlite3.connect(backup)
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)")
        connection.execute("INSERT INTO metadata VALUES('schema_version','35')")
        connection.commit()
        connection.close()
        backup.chmod(0o600)
        host = self.module.SystemRollbackHost()

        self.assertTrue(host._protected_backup_check(backup))
        backup.chmod(0o666)
        self.assertFalse(host._protected_backup_check(backup))
        backup.chmod(0o600)
        hardlink = backup_root / backup.name.replace("000000Z", "000001Z")
        os.link(backup, hardlink)
        self.assertFalse(host._protected_backup_check(backup))
        hardlink.unlink()
        symlink = backup_root / backup.name.replace("000000Z", "000002Z")
        symlink.symlink_to(backup)
        self.assertFalse(host._protected_backup_check(symlink))
        fake = type(
            "Stat",
            (),
            {
                "st_mode": stat.S_IFREG | 0o600,
                "st_uid": os.geteuid() + 1,
                "st_gid": os.getegid(),
                "st_nlink": 1,
                "st_size": backup.stat().st_size,
                "st_dev": 1,
                "st_ino": 1,
                "st_mtime_ns": 1,
                "st_ctime_ns": 1,
            },
        )()
        real_fstat = self.module.os.fstat
        with mock.patch.object(
            self.module.os,
            "fstat",
            side_effect=lambda descriptor: (
                fake if descriptor >= 0 else real_fstat(descriptor)
            ),
        ):
            self.assertFalse(host._protected_backup_check(backup))

    def test_restored_state_revalidates_protected_backup_and_mount_state_shares(
        self,
    ) -> None:
        backup_root = self.root / "backups"
        backup_root.mkdir()
        invalid = backup_root / "catalog-schema-34-p-invalid.sqlite3"
        invalid.write_bytes(b"not-sqlite")
        host = self.module.SystemRollbackHost()
        def sqlite_check(path: Path, **_kwargs) -> bool:
            return path != invalid

        with (
            mock.patch.object(
                self.module, "_PROTECTED_BACKUP_ROOT", backup_root, create=True
            ),
            mock.patch.object(host, "_sqlite_check", side_effect=sqlite_check),
            mock.patch.object(host, "_share_state_check", return_value=True) as shares,
            self.assertRaisesRegex(
                self.module.RollbackError, "restored catalog failed validation"
            ),
        ):
            host.revalidate_restored_state(mock.sentinel.manifest)
        shares.assert_called_once_with(
            Path("/var/lib/lto-archiver-share-broker"),
            Path("/etc/lto-archiver/share-credentials"),
        )

    def test_restored_state_rejects_invalid_mount_state_shares(self) -> None:
        backup_root = self.root / "backups-valid"
        backup_root.mkdir(mode=0o750)
        backup = backup_root / (
            "20260831T120000000000Z-abcdef123456-p-v35-"
            "0123456789abcdef.sqlite3"
        )
        backup.write_bytes(b"verified-by-test-double")
        host = self.module.SystemRollbackHost()

        with (
            mock.patch.object(
                self.module, "_PROTECTED_BACKUP_ROOT", backup_root, create=True
            ),
            mock.patch.object(host, "_protected_backup_check", return_value=True),
            mock.patch.object(host, "_sqlite_check", return_value=True),
            mock.patch.object(host, "_share_state_check", return_value=False),
            self.assertRaisesRegex(
                self.module.RollbackError, "restored catalog failed validation"
            ),
        ):
            host.revalidate_restored_state(mock.sentinel.manifest)

    def test_stop_captures_unit_enablement_before_runtime_masks(self) -> None:
        host = self.module.SystemRollbackHost()
        host._require_tool = lambda _path: None
        states = {
            unit: (
                "enabled"
                if unit.endswith(".socket") or unit == "lto-archiver-web.service"
                else "static"
            )
            for unit in self.module.STOP_UNITS
        }
        commands: list[tuple[str, ...]] = []
        masked = False

        def run(argv, accepted=(0,)):
            nonlocal masked
            command = tuple(str(item) for item in argv)
            commands.append(command)
            if command[0] == str(self.module._FINDMNT):
                return subprocess.CompletedProcess(command, 1, "", "")
            if command[1] == "is-enabled":
                if masked:
                    return subprocess.CompletedProcess(
                        command, 1, "masked-runtime\n", ""
                    )
                state = states[command[-1]]
                return subprocess.CompletedProcess(command, 0, f"{state}\n", "")
            if command[1] == "mask":
                masked = True
            if command[1] == "is-active":
                return subprocess.CompletedProcess(command, 3, "inactive\n", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        host._run = run
        with mock.patch.object(Path, "glob", return_value=()):
            host.mask_stop_and_prove_idle(self.module.STOP_UNITS)

        self.assertEqual(states, dict(host.captured_enablement()))
        mask_index = next(
            index for index, command in enumerate(commands) if command[1] == "mask"
        )
        enablement_indexes = [
            index
            for index, command in enumerate(commands)
            if command[1] == "is-enabled"
        ]
        self.assertEqual(len(self.module.STOP_UNITS), len(enablement_indexes))
        self.assertTrue(all(index < mask_index for index in enablement_indexes))

    def test_restore_restops_runtime_masked_stack_without_recapturing_enablement(self):
        host = self.module.SystemRollbackHost()
        host._require_tool = lambda _path: None
        commands: list[tuple[str, ...]] = []

        def run(argv, accepted=(0,)):
            command = tuple(str(item) for item in argv)
            commands.append(command)
            if command[0] == str(self.module._FINDMNT):
                return subprocess.CompletedProcess(command, 1, "", "")
            if command[1] == "is-active":
                return subprocess.CompletedProcess(command, 3, "inactive\n", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        host._run = run
        host.captured_enablement = mock.Mock(
            side_effect=self.module.RollbackError(
                "masked-runtime is not predecessor enablement"
            )
        )

        with mock.patch.object(Path, "glob", return_value=()):
            host.remask_stop_and_prove_idle(self.module.STOP_UNITS)

        host.captured_enablement.assert_not_called()
        self.assertEqual(
            ("/usr/bin/systemctl", "mask", "--runtime", *self.module.STOP_UNITS),
            commands[0],
        )
        self.assertEqual(
            len(self.module.STOP_UNITS),
            sum(command[1] == "stop" for command in commands),
        )

    def test_restore_injected_failure_reverses_each_completed_swap_and_keeps_services_masked(self):
        manifest = self._create()
        self.host.fail_swap = manifest.snapshots[3].identity
        result = self.module.restore_bundle(self.root / "rollback", self.host)
        self.assertEqual("blocked", result.status)
        self.assertEqual(
            list(reversed(self.host.swap_calls[:-1])), self.host.reverse_calls
        )
        self.assertTrue(self.host.masked)
        self.assertIn("keep-masked", self.host.calls)

        self._set_rpm_evidence()
        self._create("old-health")
        self.host.reverse_calls.clear()
        self.host.fail_swap = None
        self.host.old_health = False
        result = self.module.restore_bundle(self.root / "old-health", self.host)
        self.assertEqual("blocked", result.status)
        self.assertEqual([], self.host.reverse_calls)
        self.assertTrue(self.host.masked)

        transaction = self.root / "swap-transaction"
        transaction.mkdir()
        target = transaction / "state"
        replacement = transaction / "replacement"
        recovery = transaction / "recovery"
        recovery.mkdir()
        target.mkdir()
        replacement.mkdir()
        (target / "old").write_text("old")
        (replacement / "new").write_text("new")
        real_replace = os.replace

        def fail_install(source, destination):
            if Path(source) == replacement and Path(destination) == target:
                raise OSError("injected second rename failure")
            return real_replace(source, destination)

        with mock.patch.object(self.module.os, "replace", side_effect=fail_install):
            with self.assertRaises(OSError):
                self.module.SystemRollbackHost().swap_snapshot(
                    "configuration",
                    self.module.StagedSwap(((target, replacement),)),
                    recovery,
                )
        self.assertTrue((target / "old").is_file())

    def test_restore_journal_reports_only_the_fixed_failed_stage(self) -> None:
        redacted_path = "/synthetic/operator/recovery-path"
        stages = (
            ("platform_state", "restore_platform_state"),
            ("protected_catalog", "restore_protected_catalog"),
            ("revalidate", "revalidate_restored_state"),
            ("activation", "activate_old_stack"),
            ("health", "verify_old_health"),
        )

        for index, (stage, method_name) in enumerate(stages):
            with self.subTest(stage=stage):
                self.host = FakeRollbackHost(self.module, self.root)
                self._set_rpm_evidence()
                bundle_name = f"stage-failure-{index}"
                manifest = self._create(bundle_name)

                def fail_stage(*_args, **_kwargs):
                    raise RuntimeError(redacted_path)

                setattr(self.host, method_name, fail_stage)
                result = self.module.restore_bundle(
                    self.root / bundle_name, self.host
                )
                journal = (
                    result.failed_new_state_dir / "restore.journal"
                ).read_text()

                self.assertEqual("blocked", result.status)
                self.assertEqual(f"stage={stage}", result.detail)
                self.assertIn(f"stage-started:{stage}\n", journal)
                self.assertNotIn(f"stage-complete:{stage}\n", journal)
                self.assertTrue(journal.endswith(f"restore-blocked:{stage}\n"))
                self.assertNotIn(redacted_path, result.detail)
                self.assertNotIn(redacted_path, journal)
                self.assertEqual(manifest.bundle_id, result.bundle_id)

    def test_restore_journal_closes_each_fixed_stage_before_success(self) -> None:
        self._create()

        result = self.module.restore_bundle(self.root / "rollback", self.host)
        journal = (
            result.failed_new_state_dir / "restore.journal"
        ).read_text().splitlines()

        expected_stage_events = [
            event
            for stage in (
                "platform_state",
                "protected_catalog",
                "revalidate",
                "activation",
                "health",
            )
            for event in (f"stage-started:{stage}", f"stage-complete:{stage}")
        ]
        self.assertEqual(
            [*expected_stage_events, "restore-complete"],
            journal[-11:],
        )

    def test_restore_accepts_existing_runtime_masks_and_activates_before_health_gate(self):
        self._create()
        self.host.masked = True

        def reject_enablement_recapture(_units):
            raise self.module.RollbackError(
                "masked-runtime is not predecessor enablement"
            )

        self.host.mask_stop_and_prove_idle = reject_enablement_recapture

        result = self.module.restore_bundle(self.root / "rollback", self.host)

        self.assertEqual("restored", result.status)
        self.assertFalse(self.host.masked)
        self.assertIn(
            "remask-stop:" + ",".join(self.module.STOP_UNITS), self.host.calls
        )
        remask_index = self.host.calls.index(
            "remask-stop:" + ",".join(self.module.STOP_UNITS)
        )
        install_index = self.host.calls.index(
            "install:lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm"
        )
        activation_index = self.host.calls.index("activate-old")
        self.assertLess(remask_index, install_index)
        self.assertLess(install_index, activation_index)
        self.assertLess(
            activation_index,
            self.host.calls.index("verify-old-health"),
        )

    def test_restore_capacity_refusal_precedes_stop_install_and_recovery_creation(self):
        self._create()
        bundle = self.root / "rollback"
        self.host.calls.clear()
        self.host.restore_capacity = False
        with self.assertRaisesRegex(self.module.RollbackError, "capacity"):
            self.module.restore_bundle(bundle, self.host)
        self.assertIn("restore-capacity", self.host.calls)
        self.assertFalse(any(call.startswith(("remask-stop:", "install:", "stage:", "journal:"))
                             for call in self.host.calls))
        self.assertNotIn("keep-masked", self.host.calls)
        self.assertEqual([], list(self.root.glob("failed-new-*")))
        self.assertTrue(bundle.is_dir())

    def test_standalone_restore_holds_bundle_lease_across_verification_and_restore(self):
        self._create()
        self.host.calls.clear()
        observed = []
        verifier = self.host.verify_bundle_security

        def verify_under_lease(bundle):
            observed.append(self.host.artifact_lease_active)
            return verifier(bundle)

        self.host.verify_bundle_security = verify_under_lease
        result = self.module.restore_bundle(self.root / "rollback", self.host)
        self.assertEqual("restored", result.status)
        self.assertEqual([True], observed)
        self.assertLess(self.host.calls.index("artifact-lease-enter"), self.host.calls.index("restore-capacity"))
        self.assertLess(self.host.calls.index("verify-old-health"), self.host.calls.index("artifact-lease-exit"))

    def test_standalone_restore_lease_refusal_has_no_host_mutation(self):
        self._create()
        self.host.calls.clear()
        self.host.artifact_lease_busy = True
        with self.assertRaisesRegex(self.module.RollbackError, "lease"):
            self.module.restore_bundle(self.root / "rollback", self.host)
        self.assertFalse(any(call.startswith(("remask-stop:", "install:", "stage:")) for call in self.host.calls))
        self.assertFalse(self.host.masked)

    def test_restore_checks_remaining_capacity_before_stopping_the_stack(self):
        self._create()
        self.host.calls.clear()
        result = self.module.restore_bundle(self.root / "rollback", self.host)
        self.assertEqual("restored", result.status)
        self.assertIn("restore-capacity", self.host.calls)
        self.assertLess(self.host.calls.index("restore-capacity"),
                        self.host.calls.index("remask-stop:" + ",".join(self.module.STOP_UNITS)))

    def test_restore_success_keeps_failed_new_state_and_old_bundle_until_explicit_finalization(self):
        manifest = self._create()
        bundle = self.root / "rollback"
        result = self.module.restore_bundle(bundle, self.host)
        self.assertEqual("restored", result.status)
        self.assertTrue(bundle.is_dir())
        self.assertTrue(result.failed_new_state_dir.is_dir())
        self.assertTrue((result.failed_new_state_dir / "restore.journal").is_file())

        old_contract = json.loads(
            (bundle / "contracts/old-live-contract.json").read_text()
        )
        commands: list[tuple[str, ...]] = []
        system = self.module.SystemRollbackHost()
        system._verified_bundle = bundle
        system._basic_old_health = lambda _manifest, _probe: True
        system._require_tool = lambda _path: None
        system.captured_installed_package_state = lambda: old_contract[
            "installed_package_state"
        ]

        def run_legacy(argv, accepted=(0,)):
            command = tuple(str(item) for item in argv)
            commands.append(command)
            output = Path(command[command.index("--json-output") + 1])
            output.write_bytes(
                self.module._canonical({"schema": 1, "status": "green"})
            )
            return subprocess.CompletedProcess(command, 0, "", "")

        system._run = run_legacy
        health_recovery = self.root / "restored-health"
        health_recovery.mkdir(mode=0o700)
        system.parent_is_secure = lambda path: path == health_recovery
        system.begin_restore_health_window(health_recovery)
        self.assertTrue(system.verify_old_health(manifest))
        self.assertEqual(
            bundle / "tools/verify-deployment-rhel9.py",
            Path(commands[0][2]),
        )


if __name__ == "__main__":
    unittest.main()
