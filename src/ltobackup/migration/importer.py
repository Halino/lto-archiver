"""Offline activation of a verified Windows frozen-job bundle."""

from __future__ import annotations

import ctypes
import errno
import os
import sqlite3
import stat
import tempfile
import uuid
from collections.abc import Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from ltobackup.catalog import SCHEMA_VERSION, Catalog
from ltobackup.daemon.backups import BackupManager
from ltobackup.errors import CatalogError, ValidationError
from ltobackup.linux_settings import LinuxPaths

from .archive import VerifiedBundle, canonical_json, read_bundle, sha256_bytes
from .models import AcceptanceReport, MigrationRejected
from .validator import MigrationValidator, canonical_cassette_plan_sha256

_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_OPEN_FLAGS = (
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
)
_RENAME_NOREPLACE = 1
_RECEIPT_DIRECTORY = "migrations"
_RECEIPT_NAME = "windows-import-acceptance.json"


@dataclass(frozen=True)
class PathMappings:
    """Exact source-value to Linux-value mappings admitted during import."""

    library_roots: Mapping[str, str | Path]
    device_names: Mapping[str, str | Path]
    mount_paths: Mapping[str, str | Path]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "library_roots", MappingProxyType(dict(self.library_roots))
        )
        object.__setattr__(
            self, "device_names", MappingProxyType(dict(self.device_names))
        )
        object.__setattr__(
            self, "mount_paths", MappingProxyType(dict(self.mount_paths))
        )


class MigrationImporter:
    """Clone, migrate, remap, freeze, and activate a canonical bundle offline."""

    def __init__(self, *, backup_retention: int = 5) -> None:
        if (
            isinstance(backup_retention, bool)
            or not isinstance(backup_retention, int)
            or backup_retention < 1
        ):
            raise ValidationError("backup retention must be a positive integer")
        self.backup_retention = backup_retention

    def import_bundle(
        self,
        bundle: Path | VerifiedBundle,
        paths: LinuxPaths,
        mappings: PathMappings,
        *,
        acceptance_receipt: bytes | None = None,
    ) -> AcceptanceReport:
        paths = _validated_linux_paths(paths)
        verified = _verify_bundle(bundle)
        if acceptance_receipt is not None:
            expected_receipt = build_import_acceptance_receipt(verified, mappings)
            if acceptance_receipt != expected_receipt:
                raise MigrationRejected("acceptance-receipt-invalid")
        source_schema = _catalog_schema(verified)
        if source_schema > SCHEMA_VERSION:
            raise MigrationRejected("bundle-schema-newer-than-runtime")
        if acceptance_receipt is not None and _existing_import_matches(
            paths,
            verified,
            acceptance_receipt,
            source_schema,
        ):
            return verified.acceptance

        with _staged_state(paths) as staging:
            staged_catalog = staging.root / "catalog.db"
            staged_backups = staging.root / "backups"
            verified.extract_catalog(staged_catalog)
            manager = BackupManager(
                staged_catalog,
                staged_backups,
                retention=self.backup_retention,
            )
            try:
                manager.prepare_and_initialize()
                manager.create("before-windows-import", protected=True)
                with Catalog(staged_catalog) as catalog:
                    pre = MigrationValidator.inspect(
                        catalog, verified.acceptance.job_id
                    )
                    pre.require_valid()
                    if pre.assignment_sha256 != verified.acceptance.assignment_sha256:
                        raise MigrationRejected("assignment-hash-changed-before-import")
                    _canonicalize_untouched_format_cassettes(catalog, pre.job_id)
                    remap = _resolve_exact_mappings(catalog, pre.job_id, mappings)
                    catalog.remap_imported_job_paths(
                        pre.job_id,
                        remap.library_roots_by_id,
                        remap.device_name,
                        remap.mount_path,
                    )
                    catalog.freeze_imported_job(
                        pre.job_id,
                        pre.assignment_sha256,
                        canonical_cassette_plan_sha256(
                            catalog.connection,
                            pre.job_id,
                            assignment_sha256=pre.assignment_sha256,
                        ),
                        verified.bundle_sha256,
                    )
                    post = MigrationValidator.inspect(catalog, pre.job_id)
                    post.require_valid()
                    if post != pre:
                        raise MigrationRejected("assignment-changed-during-import")
                    _require_current_valid_catalog(catalog)
                    if acceptance_receipt is not None:
                        _require_receipt_catalog_binding(catalog, verified, post)
            except MigrationRejected:
                raise
            except (
                CatalogError,
                ValidationError,
                sqlite3.DatabaseError,
                OSError,
            ) as exc:
                raise MigrationRejected("import-staging-failed") from exc

            protected_backups = _require_protected_backups(manager, source_schema)
            if acceptance_receipt is not None:
                _write_acceptance_receipt(staging.stage_fd, acceptance_receipt)
            try:
                _publish_staged_state(
                    staging,
                    protected_backups,
                    acceptance_receipt=acceptance_receipt,
                )
            except MigrationRejected:
                raise
            except OSError as exc:
                raise MigrationRejected("state-activation-failed") from exc
            return post


def build_import_acceptance_receipt(
    bundle: VerifiedBundle,
    mappings: PathMappings,
) -> bytes:
    """Build the exact redacted receipt admitted into the atomic state tree."""

    if not isinstance(bundle, VerifiedBundle) or not isinstance(mappings, PathMappings):
        raise MigrationRejected("acceptance-receipt-invalid")
    report = bundle.acceptance
    report.require_valid()
    mapping_document = {
        "device_names": {
            source: str(destination)
            for source, destination in mappings.device_names.items()
        },
        "library_roots": {
            source: str(destination)
            for source, destination in mappings.library_roots.items()
        },
        "mount_paths": {
            source: str(destination)
            for source, destination in mappings.mount_paths.items()
        },
    }
    return canonical_json(
        {
            "acceptance_receipt_stored": True,
            "accepted": True,
            "activated_at": None,
            "activated_by_operation": None,
            "activated_schema_version": SCHEMA_VERSION,
            "assignment_sha256": report.assignment_sha256,
            "authority_state": "pre_cutover",
            "bundle_sha256": bundle.bundle_sha256,
            "catalog_sha256": bundle.catalog_sha256,
            "completed_sequences": list(report.completed_sequences),
            "error_codes": [],
            "job_id_sha256": sha256_bytes(report.job_id.encode("utf-8")),
            "mapping_sha256": sha256_bytes(canonical_json(mapping_document)),
            "media_accesses": list(report.media_accesses),
            "next_sequence": report.next_sequence,
            "policy_kind": "frozen-allocation",
            "rollback_allowed": True,
            "total_cassettes": report.total_cassettes,
            "windows_authority": "resumable",
        }
    )


@dataclass(frozen=True)
class _ResolvedMappings:
    library_roots_by_id: Mapping[str, str]
    device_name: str
    mount_path: str


def _canonicalize_untouched_format_cassettes(catalog: Catalog, job_id: str) -> None:
    with catalog.transaction() as db:
        db.execute(
            "UPDATE automatic_cassettes SET reuse_registered=0, started_at=NULL "
            "WHERE job_id=? AND operation='format' "
            "AND status IN ('pending', 'waiting_media')",
            (job_id,),
        )


@dataclass
class _StateStaging:
    parent_path: Path
    parent_fd: int
    parent_identity: tuple[int, int]
    target_name: str
    stage_name: str
    stage_fd: int
    published: bool = False

    @property
    def root(self) -> Path:
        return Path(f"/proc/self/fd/{self.stage_fd}")


def _validated_linux_paths(paths: LinuxPaths) -> LinuxPaths:
    if not isinstance(paths, LinuxPaths):
        raise MigrationRejected("linux-paths-invalid")
    state_dir = Path(paths.state_dir)
    if not state_dir.is_absolute():
        raise MigrationRejected("linux-paths-invalid")
    expected = LinuxPaths.for_root(state_dir, paths.socket_path)
    if (
        Path(paths.catalog_file) != expected.catalog_file
        or Path(paths.backup_dir) != expected.backup_dir
        or Path(paths.migration_dir) != expected.migration_dir
    ):
        raise MigrationRejected("linux-paths-invalid")
    if not state_dir.parent.is_dir():
        raise MigrationRejected("state-parent-unavailable")
    return expected


@contextmanager
def _staged_state(paths: LinuxPaths) -> Iterator[_StateStaging]:
    staging = _create_staged_state(paths)
    try:
        yield staging
    finally:
        try:
            if not staging.published:
                _remove_tree_at(staging.parent_fd, staging.stage_name)
        finally:
            close_error: OSError | None = None
            for descriptor in (staging.stage_fd, staging.parent_fd):
                try:
                    os.close(descriptor)
                except OSError as exc:
                    close_error = close_error or exc
            if close_error is not None and not staging.published:
                raise close_error


def _create_staged_state(paths: LinuxPaths) -> _StateStaging:
    parent_path = paths.state_dir.parent
    target_name = paths.state_dir.name
    if target_name in {"", ".", ".."} or Path(target_name).name != target_name:
        raise MigrationRejected("linux-paths-invalid")
    try:
        parent_fd = os.open(parent_path, _DIRECTORY_OPEN_FLAGS)
    except OSError as exc:
        raise MigrationRejected("state-parent-unavailable") from exc
    stage_name: str | None = None
    stage_fd: int | None = None
    try:
        parent_stat = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise MigrationRejected("state-parent-unavailable")
        _require_target_absent(parent_fd, target_name)
        for _attempt in range(32):
            candidate = f".lto-import-{uuid.uuid4().hex}"
            try:
                os.mkdir(candidate, mode=0o750, dir_fd=parent_fd)
            except FileExistsError:
                continue
            stage_name = candidate
            break
        if stage_name is None:
            raise MigrationRejected("state-staging-unavailable")
        stage_fd = os.open(stage_name, _DIRECTORY_OPEN_FLAGS, dir_fd=parent_fd)
        if not stat.S_ISDIR(os.fstat(stage_fd).st_mode):
            raise MigrationRejected("state-staging-unavailable")
        staging = _StateStaging(
            parent_path=parent_path,
            parent_fd=parent_fd,
            parent_identity=(parent_stat.st_dev, parent_stat.st_ino),
            target_name=target_name,
            stage_name=stage_name,
            stage_fd=stage_fd,
        )
        if not staging.root.is_dir():
            raise MigrationRejected("state-staging-unavailable")
        return staging
    except BaseException:
        if stage_fd is not None:
            os.close(stage_fd)
        if stage_name is not None:
            try:
                _remove_tree_at(parent_fd, stage_name)
            except OSError:
                pass
        os.close(parent_fd)
        raise


def _require_target_absent(parent_fd: int, target_name: str) -> None:
    try:
        os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise MigrationRejected("state-unavailable") from exc
    raise MigrationRejected("state-not-empty")


@dataclass(frozen=True)
class _CatalogConnectionView:
    connection: sqlite3.Connection


def _existing_import_matches(
    paths: LinuxPaths,
    bundle: VerifiedBundle,
    receipt: bytes,
    source_schema: int,
) -> bool:
    try:
        parent_fd = os.open(paths.state_dir.parent, _DIRECTORY_OPEN_FLAGS)
    except OSError:
        return False
    state_fd: int | None = None
    try:
        parent_details = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent_details.st_mode):
            return False
        try:
            state_fd = os.open(
                paths.state_dir.name,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=parent_fd,
            )
        except OSError:
            return False
        state_details = os.fstat(state_fd)
        if (
            not stat.S_ISDIR(state_details.st_mode)
            or stat.S_IMODE(state_details.st_mode) != 0o750
            or set(os.listdir(state_fd))
            != {"catalog.db", "backups", _RECEIPT_DIRECTORY}
        ):
            return False
        state_identity = (state_details.st_dev, state_details.st_ino)
        if not _path_identity_matches(
            paths.state_dir.parent,
            parent_fd,
            (parent_details.st_dev, parent_details.st_ino),
        ):
            return False

        receipt_directory_fd = _open_unchanged_entry(
            state_fd,
            _RECEIPT_DIRECTORY,
            directory=True,
        )
        try:
            directory_details = os.fstat(receipt_directory_fd)
            if stat.S_IMODE(directory_details.st_mode) != 0o700 or set(
                os.listdir(receipt_directory_fd)
            ) != {_RECEIPT_NAME}:
                return False
            receipt_fd = _open_unchanged_entry(
                receipt_directory_fd,
                _RECEIPT_NAME,
                directory=False,
            )
            try:
                receipt_details = os.fstat(receipt_fd)
                if (
                    stat.S_IMODE(receipt_details.st_mode) != 0o600
                    or receipt_details.st_size != len(receipt)
                    or _read_exact(receipt_fd, len(receipt) + 1) != receipt
                ):
                    return False
            finally:
                os.close(receipt_fd)
        finally:
            os.close(receipt_directory_fd)

        catalog_fd = _open_unchanged_entry(state_fd, "catalog.db", directory=False)
        try:
            catalog_details = os.fstat(catalog_fd)
            if stat.S_IMODE(catalog_details.st_mode) != 0o600:
                return False
            with sqlite3.connect(
                f"file:/proc/self/fd/{catalog_fd}?mode=ro&immutable=1",
                uri=True,
            ) as connection:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA query_only = ON")
                view = _CatalogConnectionView(connection)
                report = MigrationValidator.inspect(view, bundle.acceptance.job_id)
                if report != bundle.acceptance:
                    return False
                _require_current_valid_catalog(view)
                _require_receipt_catalog_binding(view, bundle, report)
        finally:
            os.close(catalog_fd)

        backups_fd = _open_unchanged_entry(state_fd, "backups", directory=True)
        try:
            backup_directory_details = os.fstat(backups_fd)
            if stat.S_IMODE(backup_directory_details.st_mode) != 0o750:
                return False
            backup_names = tuple(os.listdir(backups_fd))
            if not backup_names:
                return False
            for name in backup_names:
                backup_fd = _open_unchanged_entry(backups_fd, name, directory=False)
                try:
                    details = os.fstat(backup_fd)
                    if stat.S_IMODE(details.st_mode) != 0o600:
                        return False
                finally:
                    os.close(backup_fd)
            records = BackupManager(
                Path("/dev/null"),
                Path(f"/proc/self/fd/{backups_fd}"),
                retention=0,
            ).list_backups(protected=True)
            required_versions = {SCHEMA_VERSION}
            if source_schema < SCHEMA_VERSION:
                required_versions.add(source_schema)
            if (
                len(records) != len(backup_names)
                or not required_versions.issubset(
                    {record.schema_version for record in records if record.verified}
                )
                or any(not record.verified for record in records)
            ):
                return False
        finally:
            os.close(backups_fd)
        return _path_identity_matches(
            paths.state_dir.parent,
            parent_fd,
            (parent_details.st_dev, parent_details.st_ino),
        ) and _target_identity_matches(
            parent_fd,
            paths.state_dir.name,
            state_fd,
            state_identity,
        )
    except (MigrationRejected, OSError, RuntimeError, sqlite3.DatabaseError):
        return False
    finally:
        if state_fd is not None:
            os.close(state_fd)
        os.close(parent_fd)


def _path_identity_matches(
    path: Path,
    anchored_fd: int,
    expected: tuple[int, int],
) -> bool:
    try:
        current_fd = os.open(path, _DIRECTORY_OPEN_FLAGS)
    except OSError:
        return False
    try:
        current = os.fstat(current_fd)
        anchored = os.fstat(anchored_fd)
        return (current.st_dev, current.st_ino) == expected and (
            anchored.st_dev,
            anchored.st_ino,
        ) == expected
    finally:
        os.close(current_fd)


def _target_identity_matches(
    parent_fd: int,
    target_name: str,
    anchored_fd: int,
    expected: tuple[int, int],
) -> bool:
    try:
        current = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
        anchored = os.fstat(anchored_fd)
    except OSError:
        return False
    return (
        stat.S_ISDIR(current.st_mode)
        and stat.S_ISDIR(anchored.st_mode)
        and (current.st_dev, current.st_ino) == expected
        and (anchored.st_dev, anchored.st_ino) == expected
    )


def _read_exact(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit
    while remaining:
        try:
            chunk = os.read(descriptor, remaining)
        except InterruptedError:
            continue
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _verify_bundle(bundle: Path | VerifiedBundle) -> VerifiedBundle:
    source_path = bundle.path if isinstance(bundle, VerifiedBundle) else Path(bundle)
    try:
        verified = read_bundle(source_path)
    except MigrationRejected as exc:
        if "schema-unsupported" in str(exc):
            raise MigrationRejected("bundle-schema-newer-than-runtime") from exc
        raise
    if isinstance(bundle, VerifiedBundle) and (
        bundle.bundle_sha256 != verified.bundle_sha256
        or bundle.catalog_sha256 != verified.catalog_sha256
        or bundle.acceptance != verified.acceptance
    ):
        raise MigrationRejected("bundle-verification-changed")
    return verified


def _catalog_schema(bundle: VerifiedBundle) -> int:
    with tempfile.TemporaryDirectory(prefix="lto-import-schema-") as temporary:
        database = bundle.extract_catalog(Path(temporary) / "catalog.db")
        try:
            with closing(
                sqlite3.connect(f"file:{database.resolve()}?mode=ro", uri=True)
            ) as connection:
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise MigrationRejected("bundle-schema-invalid") from exc
        if row is None or not isinstance(row[0], str) or not row[0].isdecimal():
            raise MigrationRejected("bundle-schema-invalid")
        return int(row[0])


def _resolve_exact_mappings(
    catalog: Catalog,
    job_id: str,
    mappings: PathMappings,
) -> _ResolvedMappings:
    if not isinstance(mappings, PathMappings):
        raise MigrationRejected("path-mappings-invalid")
    job = catalog.get_automatic_job(job_id)
    library_rows = tuple(
        catalog.connection.execute(
            """
            SELECT l.id, l.source_root
            FROM automatic_job_libraries ajl
            JOIN libraries l ON l.id=ajl.library_id
            WHERE ajl.job_id=?
            ORDER BY ajl.sequence
            """,
            (job_id,),
        )
    )
    source_roots = {row["source_root"] for row in library_rows}
    if set(mappings.library_roots) != source_roots:
        raise MigrationRejected("library-root-mappings-not-exact")
    if set(mappings.device_names) != {job["device_name"]}:
        raise MigrationRejected("device-name-mapping-not-exact")
    if set(mappings.mount_paths) != {job["mount_path"]}:
        raise MigrationRejected("mount-path-mapping-not-exact")

    library_targets: dict[str, str] = {}
    resolved_targets: set[Path] = set()
    for row in library_rows:
        target = _absolute_path(
            mappings.library_roots[row["source_root"]],
            "library-root-mapping-invalid",
        )
        try:
            resolved = target.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise MigrationRejected("library-root-unavailable") from exc
        if not resolved.is_dir() or not os.access(resolved, os.R_OK | os.X_OK):
            raise MigrationRejected("library-root-unavailable")
        if resolved in resolved_targets:
            raise MigrationRejected("library-root-target-duplicate")
        resolved_targets.add(resolved)
        library_targets[row["id"]] = str(resolved)

    device_name = str(
        _absolute_path(
            mappings.device_names[job["device_name"]],
            "device-name-mapping-invalid",
        )
    )
    mount_path = str(
        _absolute_path(
            mappings.mount_paths[job["mount_path"]],
            "mount-path-mapping-invalid",
        )
    )
    return _ResolvedMappings(
        MappingProxyType(library_targets),
        device_name,
        mount_path,
    )


def _absolute_path(value: str | Path, error_code: str) -> Path:
    if not isinstance(value, (str, Path)):
        raise MigrationRejected(error_code)
    path = Path(value)
    if not path.is_absolute() or "\x00" in str(path):
        raise MigrationRejected(error_code)
    return path


def _require_current_valid_catalog(catalog: Catalog) -> None:
    row = catalog.connection.execute(
        "SELECT value FROM metadata WHERE key='schema_version'"
    ).fetchone()
    integrity = tuple(
        item[0] for item in catalog.connection.execute("PRAGMA integrity_check")
    )
    violations = tuple(catalog.connection.execute("PRAGMA foreign_key_check"))
    if (
        row is None
        or row[0] != str(SCHEMA_VERSION)
        or integrity != ("ok",)
        or violations
    ):
        raise MigrationRejected("activated-catalog-invalid")


def _require_receipt_catalog_binding(
    catalog: Catalog,
    bundle: VerifiedBundle,
    report: AcceptanceReport,
) -> None:
    receipt_rows = tuple(
        tuple(row)
        for row in catalog.connection.execute(
            """
            SELECT bundle_sha256, assignment_sha256
            FROM migration_receipts WHERE job_id=?
            """,
            (report.job_id,),
        )
    )
    policy_rows = tuple(
        tuple(row)
        for row in catalog.connection.execute(
            """
            SELECT policy_kind, assignment_sha256, bundle_sha256,
                   authority_state, windows_authority, rollback_allowed,
                   activated_by_operation, activated_at
            FROM imported_job_policies WHERE job_id=?
            """,
            (report.job_id,),
        )
    )
    if receipt_rows != (
        (bundle.bundle_sha256, report.assignment_sha256),
    ) or policy_rows != (
        (
            "frozen-allocation",
            report.assignment_sha256,
            bundle.bundle_sha256,
            "pre_cutover",
            "resumable",
            1,
            None,
            None,
        ),
    ):
        raise MigrationRejected("acceptance-receipt-binding-invalid")


def _write_acceptance_receipt(stage_fd: int, payload: bytes) -> None:
    os.mkdir(_RECEIPT_DIRECTORY, mode=0o700, dir_fd=stage_fd)
    directory_fd = os.open(
        _RECEIPT_DIRECTORY,
        _DIRECTORY_OPEN_FLAGS,
        dir_fd=stage_fd,
    )
    try:
        receipt_fd = os.open(
            _RECEIPT_NAME,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            _write_all(receipt_fd, payload)
            os.fchmod(receipt_fd, 0o600)
            os.fsync(receipt_fd)
        finally:
            os.close(receipt_fd)
        os.fchmod(directory_fd, 0o700)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        try:
            written = os.write(descriptor, remaining)
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError(errno.EIO, "acceptance receipt write made no progress")
        remaining = remaining[written:]


def _require_protected_backups(
    manager: BackupManager,
    source_schema: int,
) -> tuple[Path, ...]:
    protected = manager.list_backups(protected=True)
    versions = {record.schema_version for record in protected if record.verified}
    required = set(range(source_schema, SCHEMA_VERSION + 1))
    if not required.issubset(versions) or any(
        not record.verified or record.path.is_symlink() or not record.path.is_file()
        for record in protected
    ):
        raise MigrationRejected("protected-backups-invalid")
    for record in protected:
        try:
            record.path.chmod(0o600)
        except OSError as exc:
            raise MigrationRejected("protected-backups-invalid") from exc
    return tuple(record.path for record in protected)


def _publish_staged_state(
    staging: _StateStaging,
    protected_backups: tuple[Path, ...],
    *,
    acceptance_receipt: bytes | None = None,
) -> None:
    _validate_and_sync_staged_tree(
        staging,
        protected_backups,
        acceptance_receipt=acceptance_receipt,
    )
    os.fsync(staging.parent_fd)
    _recheck_parent_identity(staging)
    _require_target_absent(staging.parent_fd, staging.target_name)
    try:
        _rename_noreplace(
            staging.parent_fd,
            staging.stage_name,
            staging.target_name,
        )
    except FileExistsError as exc:
        raise MigrationRejected("state-not-empty") from exc
    try:
        _recheck_parent_identity(staging)
        _sync_published_parent(staging)
    except OSError:
        try:
            _recheck_parent_identity(staging)
            if not _published_target_matches_staging(staging):
                raise MigrationRejected("state-activation-published-state-invalid")
        except BaseException:
            try:
                _rename_noreplace(
                    staging.parent_fd,
                    staging.target_name,
                    staging.stage_name,
                )
                os.fsync(staging.parent_fd)
            except BaseException as rollback_exc:
                raise MigrationRejected(
                    "state-activation-rollback-failed"
                ) from rollback_exc
            raise
        staging.published = True
        return
    except BaseException:
        try:
            _rename_noreplace(
                staging.parent_fd,
                staging.target_name,
                staging.stage_name,
            )
            os.fsync(staging.parent_fd)
        except BaseException as rollback_exc:
            raise MigrationRejected(
                "state-activation-rollback-failed"
            ) from rollback_exc
        raise
    staging.published = True


def _sync_published_parent(staging: _StateStaging) -> None:
    os.fsync(staging.parent_fd)


def _published_target_matches_staging(staging: _StateStaging) -> bool:
    try:
        target = os.stat(
            staging.target_name,
            dir_fd=staging.parent_fd,
            follow_symlinks=False,
        )
        anchored = os.fstat(staging.stage_fd)
    except OSError:
        return False
    return (
        stat.S_ISDIR(target.st_mode)
        and stat.S_ISDIR(anchored.st_mode)
        and (target.st_dev, target.st_ino) == (anchored.st_dev, anchored.st_ino)
    )


def _validate_and_sync_staged_tree(
    staging: _StateStaging,
    protected_backups: tuple[Path, ...],
    *,
    acceptance_receipt: bytes | None = None,
) -> None:
    expected_layout = {"catalog.db", "backups"}
    if acceptance_receipt is not None:
        expected_layout.add(_RECEIPT_DIRECTORY)
    if set(os.listdir(staging.stage_fd)) != expected_layout:
        raise MigrationRejected("staged-state-layout-invalid")
    catalog_fd = _open_unchanged_entry(staging.stage_fd, "catalog.db", directory=False)
    try:
        os.fchmod(catalog_fd, 0o600)
        os.fsync(catalog_fd)
    finally:
        os.close(catalog_fd)

    backups_fd = _open_unchanged_entry(staging.stage_fd, "backups", directory=True)
    try:
        expected_names = {path.name for path in protected_backups}
        if len(expected_names) != len(protected_backups):
            raise MigrationRejected("protected-backups-invalid")
        if set(os.listdir(backups_fd)) != expected_names:
            raise MigrationRejected("staged-state-layout-invalid")
        for name in sorted(expected_names):
            backup_fd = _open_unchanged_entry(backups_fd, name, directory=False)
            try:
                os.fchmod(backup_fd, 0o600)
                os.fsync(backup_fd)
            finally:
                os.close(backup_fd)
        os.fchmod(backups_fd, 0o750)
        os.fsync(backups_fd)
    finally:
        os.close(backups_fd)
    if acceptance_receipt is not None:
        receipt_directory_fd = _open_unchanged_entry(
            staging.stage_fd,
            _RECEIPT_DIRECTORY,
            directory=True,
        )
        try:
            if set(os.listdir(receipt_directory_fd)) != {_RECEIPT_NAME}:
                raise MigrationRejected("staged-state-layout-invalid")
            receipt_fd = _open_unchanged_entry(
                receipt_directory_fd,
                _RECEIPT_NAME,
                directory=False,
            )
            try:
                details = os.fstat(receipt_fd)
                if details.st_size != len(acceptance_receipt):
                    raise MigrationRejected("acceptance-receipt-changed")
                payload = os.read(receipt_fd, len(acceptance_receipt) + 1)
                if payload != acceptance_receipt:
                    raise MigrationRejected("acceptance-receipt-changed")
                os.fchmod(receipt_fd, 0o600)
                os.fsync(receipt_fd)
            finally:
                os.close(receipt_fd)
            os.fchmod(receipt_directory_fd, 0o700)
            os.fsync(receipt_directory_fd)
        finally:
            os.close(receipt_directory_fd)
    os.fchmod(staging.stage_fd, 0o750)
    os.fsync(staging.stage_fd)


def _open_unchanged_entry(parent_fd: int, name: str, *, directory: bool) -> int:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(
            name,
            _DIRECTORY_OPEN_FLAGS if directory else _FILE_OPEN_FLAGS,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise MigrationRejected("staged-state-layout-invalid") from exc
    after = os.fstat(descriptor)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(before.st_mode)
        or not expected_type(after.st_mode)
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    ):
        os.close(descriptor)
        raise MigrationRejected("staged-state-layout-invalid")
    return descriptor


def _recheck_parent_identity(staging: _StateStaging) -> None:
    try:
        current_fd = os.open(staging.parent_path, _DIRECTORY_OPEN_FLAGS)
    except OSError as exc:
        raise MigrationRejected("state-parent-changed") from exc
    try:
        current = os.fstat(current_fd)
        anchored = os.fstat(staging.parent_fd)
        if (current.st_dev, current.st_ino) != staging.parent_identity or (
            anchored.st_dev,
            anchored.st_ino,
        ) != staging.parent_identity:
            raise MigrationRejected("state-parent-changed")
    finally:
        os.close(current_fd)


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameat2(
        parent_fd,
        os.fsencode(source),
        parent_fd,
        os.fsencode(destination),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error, os.strerror(error), destination)
    raise OSError(error, os.strerror(error), destination)


def _remove_tree_at(parent_fd: int, name: str) -> None:
    try:
        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(entry.st_mode):
        os.unlink(name, dir_fd=parent_fd)
        return
    directory_fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=parent_fd)
    try:
        for child in os.listdir(directory_fd):
            _remove_tree_at(directory_fd, child)
    finally:
        os.close(directory_fd)
    os.rmdir(name, dir_fd=parent_fd)
