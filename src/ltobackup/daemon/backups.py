from __future__ import annotations

import hashlib
import re
import sqlite3
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..catalog import SCHEMA_VERSION, Catalog
from ..errors import CatalogBackupDurabilityError, CatalogError, ValidationError
from .models import OperationFence

_BACKUP_NAME = re.compile(
    r"^(?P<stamp>[0-9]{8}T[0-9]{12}Z)-(?P<nonce>[0-9a-f]{12})-"
    r"(?P<protection>[po])-v(?P<version>[0-9]+)-(?P<reason>[0-9a-f]{16})\.sqlite3$"
)


@dataclass(frozen=True)
class BackupRecord:
    path: Path
    schema_version: int
    protected: bool
    verified: bool
    created_at: str
    reason_sha256: str


class BackupManager:
    def __init__(
        self,
        database_path: Path,
        backup_directory: Path,
        retention: int = 1,
    ) -> None:
        if isinstance(retention, bool) or not isinstance(retention, int) or retention < 0:
            raise ValidationError("backup retention must be a non-negative integer")
        self.database_path = Path(database_path)
        self.backup_directory = Path(backup_directory)
        self.retention = retention

    def prepare_and_initialize(self) -> None:
        version = self._source_schema_version()
        if version is None:
            with Catalog(self.database_path) as catalog:
                catalog.initialize()
            self._verify_database(self.database_path)
            return
        if not 1 <= version <= SCHEMA_VERSION:
            raise CatalogError(f"unsupported catalog schema version: {version}")
        while version < SCHEMA_VERSION:
            protected_backup = self.create(
                f"before-schema-{version + 1}", protected=True
            )
            with Catalog(self.database_path) as catalog:
                catalog._initialize_after_protected_backup(
                    target_version=version + 1,
                    protected_backup=protected_backup,
                )
            self._verify_database(self.database_path)
            version += 1

    def create(self, reason: str, protected: bool = False) -> Path:
        return self._create(reason, protected=protected, fence=None)

    def create_for_operation(
        self,
        fence: OperationFence,
        reason: str,
        protected: bool = False,
    ) -> Path:
        return self._create(reason, protected=protected, fence=fence)

    def list_backups(
        self, protected: bool | None = None
    ) -> tuple[BackupRecord, ...]:
        if not self.backup_directory.exists():
            return ()
        records: list[BackupRecord] = []
        for path in sorted(self.backup_directory.glob("*.sqlite3"), reverse=True):
            match = _BACKUP_NAME.fullmatch(path.name)
            if match is None:
                continue
            is_protected = match["protection"] == "p"
            if protected is not None and is_protected is not protected:
                continue
            verified = self._is_verified(path)
            records.append(
                BackupRecord(
                    path=path,
                    schema_version=int(match["version"]),
                    protected=is_protected,
                    verified=verified,
                    created_at=self._created_at(match["stamp"]),
                    reason_sha256=match["reason"],
                )
            )
        return tuple(records)

    def _create(
        self,
        reason: str,
        *,
        protected: bool,
        fence: OperationFence | None,
    ) -> Path:
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationError("backup reason is required")
        version = self._source_schema_version()
        if version is None:
            raise CatalogError("catalog is not initialized")
        self.backup_directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        reason_digest = hashlib.sha256(reason.encode("utf-8")).hexdigest()[:16]
        protection = "p" if protected else "o"
        destination = self.backup_directory / (
            f"{stamp}-{uuid.uuid4().hex[:12]}-{protection}-v{version}-"
            f"{reason_digest}.sqlite3"
        )
        try:
            with Catalog(self.database_path) as catalog:
                if fence is not None:
                    # This is intentionally adjacent to opening the SQLite snapshot.
                    catalog.assert_operation_fence(fence)
                catalog.backup_to(destination)
            self._verify_database(destination)
        except CatalogBackupDurabilityError:
            raise
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        if not protected:
            self._prune(verified_new=destination)
        return destination

    def _prune(self, *, verified_new: Path) -> None:
        """Retire ordinary copies only after their replacement passed verification.

        Do not integrity-scan backups destined for deletion, or reverify the copy
        just created. Large catalogs otherwise turn a retention pass into many
        full database reads before the tape worker can even identify media.
        Protected migration backups and unrelated files are never candidates.
        """
        ordinary = []
        for path in sorted(self.backup_directory.glob("*.sqlite3"), reverse=True):
            match = _BACKUP_NAME.fullmatch(path.name)
            if (match is not None and match["protection"] == "o"
                    and not path.is_symlink() and path.is_file()):
                ordinary.append(path)
        # A later publisher owns retirement now. This also fails safely if the
        # wall clock moved backwards: retaining an extra copy beats deleting a
        # newer writer's only verified recovery point.
        if not ordinary or ordinary[0] != verified_new:
            return
        keep = {verified_new}
        for path in ordinary:
            if len(keep) >= max(self.retention, 1):
                break
            if path != verified_new and self._is_verified(path):
                keep.add(path)
        for path in ordinary:
            if path not in keep:
                path.unlink(missing_ok=True)

    def _source_schema_version(self) -> int | None:
        if not self.database_path.exists() or self.database_path.stat().st_size == 0:
            return None
        try:
            with closing(sqlite3.connect(self.database_path)) as connection:
                table = connection.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type='table' AND name='metadata'
                    """
                ).fetchone()
                if table is None:
                    return None
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise CatalogError("catalog schema could not be read") from exc
        if row is None:
            return None
        try:
            return int(row[0])
        except (TypeError, ValueError) as exc:
            raise CatalogError("catalog schema version is invalid") from exc

    @staticmethod
    def _verify_database(path: Path) -> None:
        try:
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA foreign_keys=ON")
                integrity = [row[0] for row in connection.execute("PRAGMA integrity_check")]
                violations = list(connection.execute("PRAGMA foreign_key_check"))
        except sqlite3.DatabaseError as exc:
            raise CatalogError("catalog backup verification failed") from exc
        if integrity != ["ok"] or violations:
            raise CatalogError("catalog backup verification failed")

    @classmethod
    def _is_verified(cls, path: Path) -> bool:
        try:
            cls._verify_database(path)
        except CatalogError:
            return False
        return True

    @staticmethod
    def _created_at(stamp: str) -> str:
        parsed = datetime.strptime(stamp, "%Y%m%dT%H%M%S%fZ").replace(
            tzinfo=timezone.utc
        )
        return parsed.isoformat(timespec="microseconds")
