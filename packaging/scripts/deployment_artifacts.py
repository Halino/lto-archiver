"""Owned rollback-bundle retention, separate from deployment success.

The caller supplies full verification for the new release and a fail-closed
host proof of no open references or external leases before pruning each old
bundle. Historical bundles use their registered inventory, not the current
release's predecessor-compatibility rules. Unregistered artifacts are never
discovered or deleted. Consumers must hold ``lease`` while using a registered
bundle; all registry writers and deletion share one exclusive lock.
"""

import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from contextlib import ExitStack, contextmanager
from pathlib import Path

_ROOT_UID = 0
_ROOT_GID = 0
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_REGISTRY_LIMIT = 32 * 1024 * 1024
_STORAGE_ROOTS = (Path("/home"), Path("/var/tmp"), Path("/tmp"))


class RetentionError(RuntimeError):
    pass


def _require(condition, code):
    if not condition:
        raise RetentionError(code)


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate_registry_key")
        result[key] = value
    return result


def _identity(details):
    return [details.st_dev, details.st_ino, details.st_uid, details.st_gid,
            stat.S_IMODE(details.st_mode), details.st_size,
            details.st_mtime_ns, details.st_ctime_ns]


def _owned(details, *, directory=False, snapshot=False):
    # Only sealed snapshots/<identity>/... retain source service metadata.
    # The root-owned bundle and snapshots container exclude service writers.
    if not snapshot:
        _require(details.st_uid == _ROOT_UID and details.st_gid == _ROOT_GID,
                 "artifact_owner_changed")
        _require(not stat.S_IMODE(details.st_mode) & 0o022, "unsafe_artifact_permissions")
    if directory:
        _require(stat.S_ISDIR(details.st_mode), "unsafe_artifact_directory")
    else:
        _require(stat.S_ISREG(details.st_mode) and details.st_nlink == 1,
                 "unsafe_artifact_file")


def _snapshot_entry(relative):
    parts = relative.split("/")
    return len(parts) >= 2 and parts[0] == "snapshots"


def _canonical_path(path):
    path = Path(path)
    _require(path.is_absolute() and path.resolve(strict=True) == path,
             "redirected_artifact_path")
    return path


def _proof(callback, path):
    _require(callable(callback), "missing_artifact_proof")
    _require(callback(path) is None, "invalid_artifact_proof_result")


def _not_mounted(path):
    # st_dev alone misses bind mounts on the same filesystem.
    with open("/proc/self/mountinfo", encoding="utf-8") as stream:
        for line in stream:
            fields = line.split()
            _require(len(fields) >= 10 and "-" in fields, "mount_observation_incomplete")
            mount = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4])
            _require(mount != str(path) and not mount.startswith(str(path) + "/"),
                     "artifact_is_mounted")


def _inventory(path):
    """Hash regular single-link files through pinned, no-follow descriptors."""
    path = _canonical_path(path)
    _not_mounted(path)
    root = os.open(path, _DIRECTORY)
    try:
        root_details = os.fstat(root)
        _owned(root_details, directory=True)
        _require(stat.S_IMODE(root_details.st_mode) == 0o700, "bundle_not_private")
        inventory = {}

        def visit(directory, prefix):
            start = os.fstat(directory)
            _owned(start, directory=True, snapshot=_snapshot_entry(prefix))
            if prefix == "snapshots":
                _require(stat.S_IMODE(start.st_mode) == 0o700, "snapshots_container_not_private")
            _require(start.st_dev == root_details.st_dev, "artifact_crosses_filesystem")
            inventory[prefix] = {"kind": "directory", "identity": _identity(start)}
            for name in sorted(os.listdir(directory)):
                relative = name if not prefix else prefix + "/" + name
                observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISDIR(observed.st_mode):
                    child = os.open(name, _DIRECTORY, dir_fd=directory)
                    try:
                        _require(_identity(observed) == _identity(os.fstat(child)),
                                 "artifact_identity_changed")
                        visit(child, relative)
                    finally:
                        os.close(child)
                else:
                    _owned(observed, snapshot=_snapshot_entry(relative))
                    _require(observed.st_dev == root_details.st_dev, "artifact_crosses_filesystem")
                    child = os.open(name, _READ, dir_fd=directory)
                    try:
                        _require(_identity(observed) == _identity(os.fstat(child)),
                                 "artifact_identity_changed")
                        digest = hashlib.sha256()
                        while chunk := os.read(child, 1024 * 1024):
                            digest.update(chunk)
                        _require(_identity(observed) == _identity(os.fstat(child)),
                                 "artifact_changed_during_read")
                    finally:
                        os.close(child)
                    inventory[relative] = {"kind": "file", "identity": _identity(observed),
                                           "sha256": digest.hexdigest()}
            _require(_identity(start) == _identity(os.fstat(directory)),
                     "artifact_directory_changed")

        visit(root, "")
        _require(_identity(root_details) == _identity(path.stat(follow_symlinks=False)),
                 "artifact_root_changed")
        return inventory
    finally:
        os.close(root)


def _remaining_inventory(path, original, *, pruning):
    current = _inventory(path)
    if not pruning:
        _require(current == original, "old_bundle_changed")
        return current
    # A durable pruning record permits missing owned entries after a crash.
    # Surviving files remain byte/identity-exact; removing known children may
    # change only directory size/mtime/ctime, never identity/ownership/mode.
    for relative, observed in current.items():
        expected = original.get(relative)
        _require(expected is not None and observed["kind"] == expected["kind"],
                 "unknown_artifact_entry")
        if observed["kind"] == "directory":
            _require(observed["identity"][:5] == expected["identity"][:5],
                     "old_bundle_directory_changed")
        else:
            _require(observed == expected, "old_bundle_file_changed")
    return current


def _delete_owned(path, inventory):
    """Delete only inventoried entries, without recursive path traversal."""
    _not_mounted(path)
    parent = os.open(path.parent, _DIRECTORY)
    try:
        root = os.open(path.name, _DIRECTORY, dir_fd=parent)
        try:
            _require(_identity(os.fstat(root)) == inventory[""]["identity"],
                     "artifact_root_changed")

            def remove(directory, prefix):
                for name in sorted(os.listdir(directory)):
                    relative = name if not prefix else prefix + "/" + name
                    expected = inventory.get(relative)
                    _require(expected is not None, "unknown_artifact_entry")
                    observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    _require(_identity(observed) == expected["identity"],
                             "artifact_identity_changed")
                    if expected["kind"] == "directory":
                        child = os.open(name, _DIRECTORY, dir_fd=directory)
                        try:
                            _require(_identity(os.fstat(child)) == expected["identity"],
                                     "artifact_identity_changed")
                            remove(child, relative)
                            final = os.stat(name, dir_fd=directory, follow_symlinks=False)
                            _require((final.st_dev, final.st_ino) ==
                                     (observed.st_dev, observed.st_ino), "artifact_identity_changed")
                            os.rmdir(name, dir_fd=directory)
                        finally:
                            os.close(child)
                    else:
                        _owned(observed, snapshot=_snapshot_entry(relative))
                        os.unlink(name, dir_fd=directory)
                os.fsync(directory)

            remove(root, "")
            observed = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            _require([observed.st_dev, observed.st_ino] == inventory[""]["identity"][:2],
                     "artifact_root_changed")
            os.rmdir(path.name, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(root)
    finally:
        os.close(parent)


class DeploymentArtifactRegistry:
    def __init__(self, registry_dir=Path("/var/lib/lto-deployment-artifacts")):
        self.path = Path(registry_dir)

    @contextmanager
    def _lock(self, *, shared=False, create=True):
        _require(os.geteuid() == _ROOT_UID, "retention_requires_root")
        _require(self.path.is_absolute(), "registry_path_not_absolute")
        if not self.path.exists():
            _require(create, "registry_disappeared")
            self.path.mkdir(mode=0o700)
            parent = os.open(self.path.parent, _DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        _canonical_path(self.path)
        directory = os.open(self.path, _DIRECTORY)
        lock = None
        try:
            details = os.fstat(directory)
            _owned(details, directory=True)
            _require(stat.S_IMODE(details.st_mode) == 0o700, "registry_not_private")
            lock = os.open("registry.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                           0o600, dir_fd=directory)
            _owned(os.fstat(lock))
            _require(stat.S_IMODE(os.fstat(lock).st_mode) == 0o600, "registry_lock_not_private")
            fcntl.flock(lock, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
            _require((self.path.stat(follow_symlinks=False).st_dev,
                      self.path.stat(follow_symlinks=False).st_ino) ==
                     (details.st_dev, details.st_ino), "registry_identity_changed")
            yield directory
        finally:
            if lock is not None:
                os.close(lock)
            os.close(directory)

    @staticmethod
    def _read(directory):
        try:
            descriptor = os.open("registry.json", _READ, dir_fd=directory)
        except FileNotFoundError:
            return {"schema": 1, "current": None, "bundles": {}, "last_result": None}
        try:
            before = os.fstat(descriptor)
            _owned(before)
            _require(stat.S_IMODE(before.st_mode) == 0o600 and before.st_size <= _REGISTRY_LIMIT,
                     "invalid_registry_file")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = stream.read(_REGISTRY_LIMIT + 1)
            _require(_identity(before) == _identity(os.fstat(descriptor)), "registry_changed")
            state = json.loads(data, object_pairs_hook=_object)
            _require(isinstance(state, dict) and state.get("schema") == 1
                     and isinstance(state.get("bundles"), dict)
                     and (state.get("current") is None or state["current"] in state["bundles"]),
                     "invalid_registry_state")
            return state
        finally:
            os.close(descriptor)

    @staticmethod
    def _write(directory, state):
        data = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()
        _require(len(data) <= _REGISTRY_LIMIT, "registry_capacity_exceeded")
        name = ".registry-" + uuid.uuid4().hex
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, "registry.json", src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass

    def _bundle_path(self, path):
        path = _canonical_path(path)
        _require(path.parent.name == "rollback-bundles"
                 and any(path.is_relative_to(root) and path != root for root in _STORAGE_ROOTS)
                 and not path.is_relative_to(self.path) and not self.path.is_relative_to(path),
                 "path_is_not_owned_rollback_bundle")
        _require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", path.name), "invalid_bundle_name")
        return path

    def register_verified_bundle(self, bundle_dir, manifest_sha256, *, verify_bundle):
        try:
            _require(isinstance(manifest_sha256, str) and _HEX64.fullmatch(manifest_sha256),
                     "invalid_manifest_digest")
            with self._lock() as directory:
                path = self._bundle_path(bundle_dir)
                state = self._read(directory)
                for existing in state["bundles"]:
                    _require(existing == str(path) or
                             (not path.is_relative_to(existing)
                              and not Path(existing).is_relative_to(path)), "overlapping_artifact_roots")
                inventory = _inventory(path)
                _require(inventory.get("bundle-manifest.json", {}).get("sha256") == manifest_sha256,
                         "manifest_digest_changed")
                _proof(verify_bundle, path)
                _require(inventory == _inventory(path), "bundle_changed_during_verification")
                existing = state["bundles"].get(str(path))
                if existing is not None:
                    _require(existing.get("state") != "pruned"
                             and existing.get("inventory") == inventory
                             and existing.get("manifest_sha256") == manifest_sha256,
                             "registered_bundle_identity_changed")
                    return
                state["bundles"][str(path)] = {
                    "state": "registered", "manifest_sha256": manifest_sha256,
                    "inventory": inventory,
                }
                self._write(directory, state)
        except RetentionError:
            raise
        except Exception as exc:
            raise RetentionError("artifact_registration_failed") from exc

    @contextmanager
    def lease(self, bundle_dir):
        """Hold shared registry exclusion while verifying or restoring a bundle."""
        with self._lease_existing(bundle_dir, required=True):
            yield

    @contextmanager
    def lease_if_registered(self, bundle_dir):
        """Legacy restore does not create a registry or implicitly adopt bundles."""
        try:
            self.path.lstat()
        except FileNotFoundError:
            yield
            return
        except OSError as exc:
            raise RetentionError("registry_observation_failed") from exc
        with self._lease_existing(bundle_dir, required=False):
            yield

    @contextmanager
    def _lease_existing(self, bundle_dir, *, required):
        stack = ExitStack()
        try:
            directory = stack.enter_context(self._lock(shared=True, create=required))
            path = _canonical_path(bundle_dir)
            record = self._read(directory)["bundles"].get(str(path))
            _require(record is not None or not required, "bundle_not_registered")
            if record is not None:
                self._bundle_path(path)
                _require(record.get("state") in {"registered", "current", "superseded"},
                         "bundle_not_available_for_lease")
                _require(record.get("inventory") == _inventory(path), "registered_bundle_changed")
        except Exception as exc:
            stack.close()
            if isinstance(exc, RetentionError):
                raise
            raise RetentionError("artifact_lease_failed") from exc
        # Exceptions from the restore itself retain their original identity.
        with stack:
            yield

    @staticmethod
    def _evidence(path, digest, manifest_sha256):
        path = _canonical_path(path)
        _require(isinstance(digest, str) and _HEX64.fullmatch(digest), "invalid_evidence_digest")
        descriptor = os.open(path, _READ)
        try:
            before = os.fstat(descriptor)
            _owned(before)
            _require(before.st_size <= 1024 * 1024, "evidence_too_large")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = stream.read(1024 * 1024 + 1)
            _require(hashlib.sha256(data).hexdigest() == digest, "deployment_evidence_changed")
            value = json.loads(data, object_pairs_hook=_object)
            _require(isinstance(value, dict) and value.get("schema") == 1
                     and value.get("status") == "deployed"
                     and value.get("rollback_manifest_sha256") == manifest_sha256,
                     "deployment_evidence_not_successful")
            for key in ("application_manifest_sha256", "application_rpm_sha256",
                        "driver_input_sha256", "live_report_sha256",
                        "runtime_manifest_sha256", "runtime_rpm_sha256"):
                _require(isinstance(value.get(key), str) and _HEX64.fullmatch(value[key]),
                         "deployment_evidence_incomplete")
            _require(isinstance(value.get("repository_commit"), str)
                     and re.fullmatch(r"[0-9a-f]{40}", value["repository_commit"]),
                     "deployment_evidence_incomplete")
            os.fsync(descriptor)
            _require(_identity(before) == _identity(os.fstat(descriptor)), "deployment_evidence_changed")
            parent = os.open(path.parent, _DIRECTORY)
            try:
                _require(_identity(before) == _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                         "deployment_evidence_changed")
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            os.close(descriptor)

    @staticmethod
    def _mark_pruned(record):
        # Retain the audit binding, not every file entry of an absent tree.
        # Incomplete pruning keeps its full inventory for exact recovery.
        record["root_identity"] = record["inventory"][""]["identity"]
        record["state"] = "pruned"
        del record["inventory"]

    def promote_after_success(self, bundle_dir, *, evidence_path, evidence_sha256,
                              verify_bundle, prove_prunable):
        """Never turn a successfully deployed release into a rollback request."""
        result = {"status": "refused", "pruned": [], "deferred": [], "error": ""}
        promoted = False
        try:
            with self._lock() as directory:
                state = self._read(directory)
                try:
                    path = self._bundle_path(bundle_dir)
                    record = state["bundles"].get(str(path))
                    _require(record is not None and record.get("state") in {"registered", "current"},
                             "bundle_not_registered_for_promotion")
                    self._evidence(evidence_path, evidence_sha256, record["manifest_sha256"])
                    _require(_inventory(path) == record["inventory"], "new_bundle_changed")
                    _proof(verify_bundle, path)
                    _require(_inventory(path) == record["inventory"], "new_bundle_changed")
                    previous = state["current"]
                    if previous is not None and previous != str(path):
                        _require(state["bundles"][previous]["state"] == "current",
                                 "invalid_current_bundle")
                        state["bundles"][previous]["state"] = "superseded"
                    state["current"] = str(path)
                    record["state"] = "current"
                    record["evidence_sha256"] = evidence_sha256
                    record["evidence_path"] = str(evidence_path)
                    state["last_result"] = {**result, "status": "promoted"}
                    self._write(directory, state)
                    promoted = True
                    result["status"] = "promoted"
                    for obsolete, old in state["bundles"].items():
                        if obsolete == str(path) or old.get("state") not in {"superseded", "pruning"}:
                            continue
                        try:
                            if old["state"] == "pruning":
                                try:
                                    Path(obsolete).lstat()
                                except FileNotFoundError:
                                    # Deletion finished before its final journal write.
                                    # No pathname is removed on this recovery branch.
                                    self._mark_pruned(old)
                                    result["pruned"].append(obsolete)
                                    continue
                            target = self._bundle_path(obsolete)
                            partial = old["state"] == "pruning"
                            _remaining_inventory(target, old["inventory"], pruning=partial)
                            _proof(prove_prunable, target)
                            remaining = _remaining_inventory(target, old["inventory"], pruning=partial)
                            _require(_inventory(path) == record["inventory"], "new_bundle_changed")
                            old["state"] = "pruning"
                            self._write(directory, state)
                            _delete_owned(target, remaining)
                            self._mark_pruned(old)
                            result["pruned"].append(obsolete)
                        except Exception as exc:  # noqa: BLE001 - pruning must not roll back a deployed release.
                            result["deferred"].append({"path": obsolete, "error": self._error(exc)})
                    state["last_result"] = result
                    self._write(directory, state)
                except Exception as exc:  # noqa: BLE001 - preserve deployed state on retention failure.
                    result["error"] = self._error(exc)
                    if promoted:
                        result["status"] = "promoted"
                    else:
                        # Re-read rather than persisting a failed, in-memory promotion.
                        state = self._read(directory)
                    state["last_result"] = result
                    try:
                        self._write(directory, state)
                    except Exception as persistence_error:  # noqa: BLE001 - report failed error-record persistence.
                        result["persistence_error"] = self._error(persistence_error)
        except Exception as exc:  # noqa: BLE001 - public post-success boundary never requests rollback.
            result["error"] = self._error(exc)
        return result

    @staticmethod
    def _error(exc):
        return str(exc) if isinstance(exc, RetentionError) else "artifact_retention_failed"
