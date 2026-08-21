from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from .errors import CatalogError, ValidationError
from .util import utc_now, validate_id


SCHEMA_VERSION = 13
EVENT_RETENTION = 50_000


class Catalog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 30000")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA synchronous = FULL")

    def close(self) -> None:
        self.connection.close()

    def backup_to(self, destination: Path) -> Path:
        destination = Path(destination)
        if destination.resolve() == self.path.resolve():
            raise ValidationError("La copia del catalogo deve usare un file diverso dall'originale")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".tmp")
        try:
            with closing(sqlite3.connect(temporary)) as target:
                self.connection.backup(target)
            os.replace(temporary, destination)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        return destination

    def __enter__(self) -> "Catalog":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            yield self.connection
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise

    def initialize(self) -> None:
        with self.transaction() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS libraries (
                    id TEXT PRIMARY KEY COLLATE NOCASE,
                    name TEXT NOT NULL,
                    source_root TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'retired')),
                    created_at TEXT NOT NULL,
                    retired_at TEXT,
                    last_scan_files INTEGER,
                    last_scan_bytes INTEGER,
                    last_scanned_at TEXT
                );

                CREATE TABLE IF NOT EXISTS tapes (
                    id TEXT PRIMARY KEY COLLATE NOCASE,
                    cassette_number TEXT NOT NULL,
                    volume_serial TEXT NOT NULL,
                    volume_label TEXT NOT NULL,
                    filesystem TEXT NOT NULL,
                    mount_hint TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'retired')),
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS blocks (
                    id TEXT PRIMARY KEY,
                    library_id TEXT NOT NULL REFERENCES libraries(id),
                    tape_id TEXT NOT NULL REFERENCES tapes(id),
                    tape_relative_root TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('copying', 'completed', 'failed')),
                    visible INTEGER NOT NULL DEFAULT 1 CHECK(visible IN (0, 1)),
                    planned_files INTEGER NOT NULL,
                    planned_bytes INTEGER NOT NULL,
                    copied_files INTEGER NOT NULL DEFAULT 0,
                    copied_bytes INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error TEXT
                );

                CREATE TABLE IF NOT EXISTS file_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    library_id TEXT NOT NULL REFERENCES libraries(id),
                    block_id TEXT NOT NULL REFERENCES blocks(id),
                    tape_id TEXT NOT NULL REFERENCES tapes(id),
                    relative_path TEXT NOT NULL,
                    tape_relative_path TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    mtime_ns INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    copied_at TEXT NOT NULL,
                    visible INTEGER NOT NULL DEFAULT 1 CHECK(visible IN (0, 1)),
                    parent_path TEXT NOT NULL DEFAULT '',
                    file_name TEXT NOT NULL DEFAULT '',
                    created_ns INTEGER,
                    accessed_ns INTEGER,
                    source_mode INTEGER,
                    windows_attributes INTEGER,
                    owner_name TEXT,
                    owner_sid TEXT,
                    security_descriptor TEXT,
                    alternate_streams_json TEXT NOT NULL DEFAULT '[]',
                    metadata_state TEXT NOT NULL DEFAULT 'legacy'
                        CHECK(metadata_state IN ('legacy', 'complete', 'partial')),
                    metadata_error TEXT
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS automatic_jobs (
                    id TEXT PRIMARY KEY COLLATE NOCASE,
                    display_name TEXT NOT NULL,
                    media_key TEXT NOT NULL DEFAULT 'LTO-6',
                    library_id TEXT NOT NULL REFERENCES libraries(id),
                    device_name TEXT NOT NULL,
                    mount_path TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN (
                        'planned', 'waiting_media', 'formatting', 'mounting', 'writing',
                        'unmounting', 'paused', 'completed', 'failed'
                    )),
                    current_sequence INTEGER NOT NULL DEFAULT 0,
                    total_cassettes INTEGER NOT NULL,
                    destructive_confirmed_at TEXT NOT NULL,
                    force_format INTEGER NOT NULL DEFAULT 0 CHECK(force_format IN (0, 1)),
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    last_error TEXT
                );

                CREATE TABLE IF NOT EXISTS automatic_cassettes (
                    job_id TEXT NOT NULL REFERENCES automatic_jobs(id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    physical_label TEXT NOT NULL COLLATE NOCASE,
                    tape_serial TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN (
                        'pending', 'waiting_media', 'formatting', 'mounting', 'writing',
                        'unmounting', 'completed', 'failed'
                    )),
                    tape_id TEXT,
                    block_id TEXT,
                    planned_files INTEGER NOT NULL,
                    planned_bytes INTEGER NOT NULL,
                    copied_files INTEGER NOT NULL DEFAULT 0,
                    copied_bytes INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT,
                    completed_at TEXT,
                    error TEXT,
                    operation TEXT NOT NULL DEFAULT 'format'
                        CHECK(operation IN ('format', 'append')),
                    reuse_registered INTEGER NOT NULL DEFAULT 0
                        CHECK(reuse_registered IN (0, 1)),
                    PRIMARY KEY(job_id, sequence),
                    UNIQUE(job_id, physical_label),
                    UNIQUE(job_id, tape_serial)
                );

                CREATE TABLE IF NOT EXISTS automatic_job_libraries (
                    job_id TEXT NOT NULL REFERENCES automatic_jobs(id) ON DELETE CASCADE,
                    library_id TEXT NOT NULL REFERENCES libraries(id),
                    sequence INTEGER NOT NULL,
                    PRIMARY KEY(job_id, library_id),
                    UNIQUE(job_id, sequence)
                );

                CREATE TABLE IF NOT EXISTS automatic_cassette_items (
                    job_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    item_sequence INTEGER NOT NULL,
                    library_id TEXT NOT NULL REFERENCES libraries(id),
                    relative_path TEXT NOT NULL COLLATE NOCASE,
                    size INTEGER NOT NULL,
                    mtime_ns INTEGER NOT NULL,
                    PRIMARY KEY(job_id, sequence, item_sequence),
                    UNIQUE(job_id, library_id, relative_path),
                    FOREIGN KEY(job_id, sequence)
                        REFERENCES automatic_cassettes(job_id, sequence) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS ix_file_versions_latest
                    ON file_versions(library_id, relative_path, id DESC);
                CREATE INDEX IF NOT EXISTS ix_file_versions_tape
                    ON file_versions(tape_id, library_id, visible);
                CREATE INDEX IF NOT EXISTS ix_blocks_library
                    ON blocks(library_id, started_at DESC);
                CREATE INDEX IF NOT EXISTS ix_automatic_cassette_items_queue
                    ON automatic_cassette_items(job_id, sequence, item_sequence);
                """
            )
            row = db.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO metadata(key, value) VALUES('schema_version', ?)",
                    (str(SCHEMA_VERSION),),
                )
            else:
                version = int(row["value"])
                if version < 1 or version > SCHEMA_VERSION:
                    raise CatalogError(
                        f"Versione catalogo {row['value']} non supportata; attesa {SCHEMA_VERSION}"
                    )
                migrations = (
                    (1, self._migrate_v1_to_v2),
                    (2, self._migrate_v2_to_v3),
                    (3, self._migrate_v3_to_v4),
                    (4, self._migrate_v4_to_v5),
                    (5, self._migrate_v5_to_v6),
                    (6, self._migrate_v6_to_v7),
                    (7, self._migrate_v7_to_v8),
                    (8, self._migrate_v8_to_v9),
                    (9, self._migrate_v9_to_v10),
                    (10, self._migrate_v10_to_v11),
                    (11, self._migrate_v11_to_v12),
                    (12, self._migrate_v12_to_v13),
                )
                for from_version, migrate in migrations:
                    if version == from_version:
                        migrate(db)
                        version += 1
            db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_tapes_cassette_number "
                "ON tapes(cassette_number COLLATE NOCASE)"
            )
            db.execute("DROP INDEX IF EXISTS ux_tapes_volume_serial")
            try:
                db.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS ux_tapes_ltfs_volume_label "
                    "ON tapes(volume_label COLLATE NOCASE) "
                    "WHERE filesystem COLLATE NOCASE = 'LTFS' AND trim(volume_label)<>''"
                )
            except sqlite3.IntegrityError as exc:
                raise CatalogError(
                    "Il catalogo contiene etichette volume LTFS duplicate; "
                    "correggerle prima di continuare"
                ) from exc
            db.execute(
                "CREATE INDEX IF NOT EXISTS ix_file_versions_parent "
                "ON file_versions(library_id, parent_path, visible, id DESC)"
            )
            reconciled = db.execute(
                """
                UPDATE file_versions SET visible=0
                WHERE visible=1 AND block_id IN (
                    SELECT id FROM blocks WHERE status='failed'
                )
                """
            ).rowcount
            if reconciled:
                self._event(
                    db,
                    "catalog.reconcile_failed_versions",
                    {"hidden_file_versions": int(reconciled)},
                )
            db.execute(
                """
                DELETE FROM events
                WHERE id <= COALESCE((SELECT MAX(id) FROM events), 0) - ?
                """,
                (EVENT_RETENTION,),
            )

    def _migrate_v1_to_v2(self, db: sqlite3.Connection) -> None:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(tapes)")}
        if "cassette_number" not in columns:
            db.execute("ALTER TABLE tapes ADD COLUMN cassette_number TEXT")
        db.execute(
            "UPDATE tapes SET cassette_number=id "
            "WHERE cassette_number IS NULL OR trim(cassette_number)=''"
        )
        db.execute(
            "UPDATE metadata SET value=? WHERE key='schema_version'",
            ("2",),
        )
        self._event(
            db,
            "catalog.migrate",
            {"from_version": 1, "to_version": 2, "cassette_number_default": "tape_id"},
        )

    def _migrate_v2_to_v3(self, db: sqlite3.Connection) -> None:
        db.execute(
            "UPDATE metadata SET value=? WHERE key='schema_version'",
            ("3",),
        )
        self._event(db, "catalog.migrate", {"from_version": 2, "to_version": 3})

    def _migrate_v3_to_v4(self, db: sqlite3.Connection) -> None:
        db.execute(
            """
            INSERT OR IGNORE INTO automatic_job_libraries(job_id, library_id, sequence)
            SELECT id, library_id, 1 FROM automatic_jobs
            """
        )
        db.execute(
            "UPDATE metadata SET value=? WHERE key='schema_version'",
            ("4",),
        )
        self._event(db, "catalog.migrate", {"from_version": 3, "to_version": 4})

    def _migrate_v4_to_v5(self, db: sqlite3.Connection) -> None:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(file_versions)")}
        additions = (
            ("parent_path", "TEXT NOT NULL DEFAULT ''"),
            ("file_name", "TEXT NOT NULL DEFAULT ''"),
            ("created_ns", "INTEGER"),
            ("accessed_ns", "INTEGER"),
            ("source_mode", "INTEGER"),
            ("windows_attributes", "INTEGER"),
            ("owner_name", "TEXT"),
            ("owner_sid", "TEXT"),
            ("security_descriptor", "TEXT"),
            ("alternate_streams_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("metadata_state", "TEXT NOT NULL DEFAULT 'legacy'"),
            ("metadata_error", "TEXT"),
        )
        for name, declaration in additions:
            if name not in columns:
                db.execute(f"ALTER TABLE file_versions ADD COLUMN {name} {declaration}")
        rows = db.execute("SELECT id, relative_path FROM file_versions").fetchall()
        db.executemany(
            "UPDATE file_versions SET parent_path=?, file_name=? WHERE id=?",
            (
                (*self._split_relative_path(row["relative_path"]), row["id"])
                for row in rows
            ),
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS ix_file_versions_parent "
            "ON file_versions(library_id, parent_path, visible, id DESC)"
        )
        db.execute("UPDATE metadata SET value=? WHERE key='schema_version'", ("5",))
        self._event(
            db,
            "catalog.migrate",
            {"from_version": 4, "to_version": 5, "file_versions_backfilled": len(rows)},
        )

    def _migrate_v5_to_v6(self, db: sqlite3.Connection) -> None:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(libraries)")}
        additions = (
            ("last_scan_files", "INTEGER"),
            ("last_scan_bytes", "INTEGER"),
            ("last_scanned_at", "TEXT"),
        )
        for name, declaration in additions:
            if name not in columns:
                db.execute(f"ALTER TABLE libraries ADD COLUMN {name} {declaration}")
        db.execute("UPDATE metadata SET value=? WHERE key='schema_version'", ("6",))
        self._event(db, "catalog.migrate", {"from_version": 5, "to_version": 6})

    def _migrate_v6_to_v7(self, db: sqlite3.Connection) -> None:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(automatic_jobs)")}
        if "force_format" not in columns:
            db.execute(
                "ALTER TABLE automatic_jobs ADD COLUMN force_format "
                "INTEGER NOT NULL DEFAULT 0 CHECK(force_format IN (0, 1))"
            )
        db.execute("UPDATE metadata SET value=? WHERE key='schema_version'", ("7",))
        self._event(
            db,
            "catalog.migrate",
            {"from_version": 6, "to_version": 7, "legacy_force_format": False},
        )

    def _migrate_v7_to_v8(self, db: sqlite3.Connection) -> None:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(automatic_jobs)")}
        if "display_name" not in columns:
            db.execute(
                "ALTER TABLE automatic_jobs ADD COLUMN display_name TEXT NOT NULL DEFAULT ''"
            )
        db.execute(
            "UPDATE automatic_jobs SET display_name=id "
            "WHERE trim(display_name)=''"
        )
        db.execute("UPDATE metadata SET value=? WHERE key='schema_version'", ("8",))
        self._event(
            db,
            "catalog.migrate",
            {"from_version": 7, "to_version": 8, "job_names_default": "job_id"},
        )

    def _migrate_v8_to_v9(self, db: sqlite3.Connection) -> None:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(automatic_jobs)")}
        if "media_key" not in columns:
            db.execute(
                "ALTER TABLE automatic_jobs ADD COLUMN media_key TEXT NOT NULL DEFAULT 'LTO-6'"
            )
        db.execute("UPDATE metadata SET value=? WHERE key='schema_version'", ("9",))
        self._event(
            db,
            "catalog.migrate",
            {"from_version": 8, "to_version": 9, "legacy_media_key": "LTO-6"},
        )

    def _migrate_v9_to_v10(self, db: sqlite3.Connection) -> None:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(automatic_cassettes)")}
        if "operation" not in columns:
            db.execute(
                "ALTER TABLE automatic_cassettes ADD COLUMN operation TEXT NOT NULL "
                "DEFAULT 'format' CHECK(operation IN ('format', 'append'))"
            )
        db.execute("UPDATE metadata SET value=? WHERE key='schema_version'", ("10",))
        self._event(
            db,
            "catalog.migrate",
            {"from_version": 9, "to_version": 10, "cassette_operation": "format"},
        )

    def _migrate_v10_to_v11(self, db: sqlite3.Connection) -> None:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS automatic_cassette_items (
                job_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                item_sequence INTEGER NOT NULL,
                library_id TEXT NOT NULL REFERENCES libraries(id),
                relative_path TEXT NOT NULL COLLATE NOCASE,
                size INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                PRIMARY KEY(job_id, sequence, item_sequence),
                UNIQUE(job_id, library_id, relative_path),
                FOREIGN KEY(job_id, sequence)
                    REFERENCES automatic_cassettes(job_id, sequence) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS ix_automatic_cassette_items_queue
                ON automatic_cassette_items(job_id, sequence, item_sequence);
            """
        )
        db.execute("UPDATE metadata SET value=? WHERE key='schema_version'", ("11",))
        self._event(
            db,
            "catalog.migrate",
            {"from_version": 10, "to_version": 11, "cassette_manifests": True},
        )

    def _migrate_v11_to_v12(self, db: sqlite3.Connection) -> None:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(automatic_cassettes)")}
        if "reuse_registered" not in columns:
            db.execute(
                "ALTER TABLE automatic_cassettes ADD COLUMN reuse_registered INTEGER "
                "NOT NULL DEFAULT 0 CHECK(reuse_registered IN (0, 1))"
            )
        db.execute("UPDATE metadata SET value=? WHERE key='schema_version'", ("12",))
        self._event(
            db,
            "catalog.migrate",
            {"from_version": 11, "to_version": 12, "registered_tape_reuse": False},
        )

    def _migrate_v12_to_v13(self, db: sqlite3.Connection) -> None:
        db.execute("DROP INDEX IF EXISTS ux_tapes_volume_serial")
        db.execute("UPDATE metadata SET value=? WHERE key='schema_version'", ("13",))
        self._event(
            db,
            "catalog.migrate",
            {
                "from_version": 12,
                "to_version": 13,
                "ltfs_identity": "volume_label",
                "win32_volume_serial": "diagnostic",
            },
        )

    @staticmethod
    def _split_relative_path(relative_path: str) -> tuple[str, str]:
        normalized = relative_path.replace("\\", "/").strip("/")
        path = PurePosixPath(normalized)
        parent = "" if str(path.parent) == "." else path.parent.as_posix()
        return parent, path.name

    def add_library(self, library_id: str, name: str, source_root: str) -> None:
        validate_id(library_id, "ID libreria")
        if not name.strip():
            raise ValidationError("Il nome della libreria è obbligatorio")
        source = Path(source_root)
        if not source.is_absolute():
            raise ValidationError("Il percorso sorgente deve essere assoluto o UNC")
        if not source.is_dir():
            raise ValidationError(f"Sorgente non accessibile o non directory: {source}")
        try:
            with self.transaction() as db:
                db.execute(
                    """
                    INSERT INTO libraries(id, name, source_root, status, created_at)
                    VALUES(?, ?, ?, 'active', ?)
                    """,
                    (library_id, name.strip(), str(source), utc_now()),
                )
                self._event(db, "library.add", {"library_id": library_id, "source_root": str(source)})
        except sqlite3.IntegrityError as exc:
            raise CatalogError(f"Libreria già presente: {library_id}") from exc

    def get_library(self, library_id: str, include_retired: bool = False) -> sqlite3.Row:
        query = "SELECT * FROM libraries WHERE id=?"
        params: tuple[Any, ...] = (library_id,)
        if not include_retired:
            query += " AND status='active'"
        row = self.connection.execute(query, params).fetchone()
        if row is None:
            raise CatalogError(f"Libreria non trovata o ritirata: {library_id}")
        return row

    def list_libraries(self, include_retired: bool = False) -> list[sqlite3.Row]:
        query = "SELECT * FROM libraries"
        if not include_retired:
            query += " WHERE status='active'"
        query += " ORDER BY id COLLATE NOCASE"
        return list(self.connection.execute(query))

    def update_library_scan(self, library_id: str, total_files: int, total_bytes: int) -> None:
        if total_files < 0 or total_bytes < 0:
            raise ValidationError("Dimensione o numero file della libreria non validi")
        scanned_at = utc_now()
        with self.transaction() as db:
            cursor = db.execute(
                """
                UPDATE libraries
                SET last_scan_files=?, last_scan_bytes=?, last_scanned_at=?
                WHERE id=?
                """,
                (total_files, total_bytes, scanned_at, library_id),
            )
            if cursor.rowcount != 1:
                raise CatalogError(f"Libreria non trovata: {library_id}")
            self._event(
                db,
                "library.scan",
                {
                    "library_id": library_id,
                    "total_files": total_files,
                    "total_bytes": total_bytes,
                },
            )

    def delete_library(self, library_id: str) -> dict[str, int | str | bool]:
        with self.transaction() as db:
            library = db.execute("SELECT id FROM libraries WHERE id=?", (library_id,)).fetchone()
            if library is None:
                raise CatalogError(f"Libreria non trovata: {library_id}")
            jobs = db.execute(
                """
                SELECT DISTINCT aj.id, aj.library_id, aj.status
                FROM automatic_jobs aj
                LEFT JOIN automatic_job_libraries ajl ON ajl.job_id=aj.id
                WHERE aj.library_id=? OR ajl.library_id=?
                """,
                (library_id, library_id),
            ).fetchall()
            unfinished = next(
                (row for row in jobs if row["status"] not in ("completed", "failed")),
                None,
            )
            if unfinished:
                raise CatalogError(
                    f"La libreria {library_id} appartiene al job non concluso {unfinished['id']}; "
                    "completare o terminare il job prima di eliminarla"
                )

            for job in jobs:
                remaining = db.execute(
                    """
                    SELECT library_id
                    FROM automatic_job_libraries
                    WHERE job_id=? AND library_id<>?
                    ORDER BY sequence
                    """,
                    (job["id"], library_id),
                ).fetchall()
                if not remaining:
                    db.execute("DELETE FROM automatic_jobs WHERE id=?", (job["id"],))
                    continue
                if job["library_id"].casefold() == library_id.casefold():
                    db.execute(
                        "UPDATE automatic_jobs SET library_id=? WHERE id=?",
                        (remaining[0]["library_id"], job["id"]),
                    )
                db.execute(
                    "DELETE FROM automatic_job_libraries WHERE job_id=? AND library_id=?",
                    (job["id"], library_id),
                )

            file_count = db.execute(
                "SELECT COUNT(*) FROM file_versions WHERE library_id=?", (library_id,)
            ).fetchone()[0]
            block_count = db.execute(
                "SELECT COUNT(*) FROM blocks WHERE library_id=?", (library_id,)
            ).fetchone()[0]
            db.execute("DELETE FROM file_versions WHERE library_id=?", (library_id,))
            db.execute("DELETE FROM blocks WHERE library_id=?", (library_id,))
            db.execute("DELETE FROM libraries WHERE id=?", (library_id,))
            self._event(
                db,
                "library.delete",
                {
                    "library_id": library_id,
                    "catalog_files_deleted": file_count,
                    "catalog_blocks_deleted": block_count,
                    "source_data_deleted": False,
                    "tape_data_deleted": False,
                },
            )
            return {
                "library_id": library_id,
                "catalog_files_deleted": file_count,
                "catalog_blocks_deleted": block_count,
                "source_data_deleted": False,
                "tape_data_deleted": False,
            }

    def register_tape(
        self,
        tape_id: str,
        volume_serial: str,
        volume_label: str,
        filesystem: str,
        mount_hint: str,
        cassette_number: str | None = None,
    ) -> None:
        validate_id(tape_id, "ID nastro")
        cassette_number = (cassette_number or tape_id).strip()
        validate_id(cassette_number, "Numero cassetta")
        now = utc_now()
        with self.transaction() as db:
            if filesystem.casefold() == "ltfs" and volume_label.strip():
                existing_label = db.execute(
                    "SELECT id FROM tapes WHERE filesystem=? COLLATE NOCASE "
                    "AND volume_label=? COLLATE NOCASE AND id<>? COLLATE NOCASE",
                    ("LTFS", volume_label, tape_id),
                ).fetchone()
                if existing_label:
                    raise CatalogError(
                        f"L'etichetta LTFS {volume_label} è già registrata come "
                        f"{existing_label['id']}"
                    )
            existing = db.execute("SELECT * FROM tapes WHERE id=?", (tape_id,)).fetchone()
            if existing and existing["cassette_number"].casefold() != cassette_number.casefold():
                raise CatalogError(
                    f"Il nastro {tape_id} è già associato al numero cassetta "
                    f"{existing['cassette_number']}"
                )
            if (
                existing
                and filesystem.casefold() != "ltfs"
                and existing["volume_serial"].casefold() != volume_serial.casefold()
            ):
                raise CatalogError(
                    f"Il nastro {tape_id} è associato al seriale {existing['volume_serial']}, non {volume_serial}"
                )
            if (
                existing
                and filesystem.casefold() == "ltfs"
                and str(existing["volume_label"]).casefold() != volume_label.casefold()
            ):
                raise CatalogError(
                    f"Il nastro {tape_id} è associato all'etichetta LTFS "
                    f"{existing['volume_label']}, non {volume_label}"
                )
            try:
                db.execute(
                    """
                INSERT INTO tapes(
                    id, cassette_number, volume_serial, volume_label, filesystem,
                    mount_hint, status, created_at, last_seen_at
                )
                VALUES(?, ?, ?, ?, ?, ?, 'active', ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    volume_serial=excluded.volume_serial,
                    volume_label=excluded.volume_label,
                    filesystem=excluded.filesystem,
                    mount_hint=excluded.mount_hint,
                    last_seen_at=excluded.last_seen_at
                    """,
                    (
                        tape_id,
                        cassette_number,
                        volume_serial,
                        volume_label,
                        filesystem,
                        mount_hint,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise CatalogError(f"Numero cassetta già registrato: {cassette_number}") from exc
            self._event(
                db,
                "tape.register",
                {"tape_id": tape_id, "cassette_number": cassette_number, "serial": volume_serial},
            )

    def get_tape(self, tape_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM tapes WHERE id=? AND status='active'", (tape_id,)
        ).fetchone()
        if row is None:
            raise CatalogError(f"Nastro non trovato o ritirato: {tape_id}")
        return row

    def list_tapes(self) -> list[sqlite3.Row]:
        return list(self.connection.execute("SELECT * FROM tapes ORDER BY id COLLATE NOCASE"))

    def touch_tape(self, tape_id: str, mount_hint: str) -> None:
        with self.transaction() as db:
            db.execute(
                "UPDATE tapes SET mount_hint=?, last_seen_at=? WHERE id=?",
                (mount_hint, utc_now(), tape_id),
            )

    def latest_versions(self, library_id: str) -> dict[str, sqlite3.Row]:
        rows = self.connection.execute(
            """
            SELECT fv.*
            FROM file_versions fv
            JOIN (
                SELECT candidate.relative_path, MAX(candidate.id) AS max_id
                FROM file_versions candidate
                JOIN blocks candidate_block ON candidate_block.id=candidate.block_id
                WHERE candidate.library_id=?
                  AND candidate.visible=1
                  AND candidate_block.status='completed'
                GROUP BY candidate.relative_path
            ) latest ON latest.max_id=fv.id
            ORDER BY fv.relative_path COLLATE NOCASE
            """,
            (library_id,),
        )
        return {row["relative_path"]: row for row in rows}

    def create_block(
        self,
        block_id: str,
        library_id: str,
        tape_id: str,
        tape_relative_root: str,
        planned_files: int,
        planned_bytes: int,
    ) -> None:
        with self.transaction() as db:
            db.execute(
                """
                INSERT INTO blocks(
                    id, library_id, tape_id, tape_relative_root, status,
                    planned_files, planned_bytes, started_at
                ) VALUES(?, ?, ?, ?, 'copying', ?, ?, ?)
                """,
                (
                    block_id,
                    library_id,
                    tape_id,
                    tape_relative_root,
                    planned_files,
                    planned_bytes,
                    utc_now(),
                ),
            )
            self._event(
                db,
                "block.start",
                {
                    "block_id": block_id,
                    "library_id": library_id,
                    "tape_id": tape_id,
                    "planned_files": planned_files,
                    "planned_bytes": planned_bytes,
                },
            )

    def record_file_version(
        self,
        library_id: str,
        block_id: str,
        tape_id: str,
        relative_path: str,
        tape_relative_path: str,
        size: int,
        mtime_ns: int,
        sha256: str,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        parent_path, file_name = self._split_relative_path(relative_path)
        details = metadata or {}
        alternate_streams = details.get("alternate_streams", [])
        with self.transaction() as db:
            cursor = db.execute(
                """
                INSERT INTO file_versions(
                    library_id, block_id, tape_id, relative_path, tape_relative_path,
                    size, mtime_ns, sha256, copied_at, parent_path, file_name,
                    created_ns, accessed_ns, source_mode, windows_attributes,
                    owner_name, owner_sid, security_descriptor, alternate_streams_json,
                    metadata_state, metadata_error
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    library_id,
                    block_id,
                    tape_id,
                    relative_path,
                    tape_relative_path,
                    size,
                    mtime_ns,
                    sha256,
                    utc_now(),
                    parent_path,
                    file_name,
                    details.get("created_ns"),
                    details.get("accessed_ns"),
                    details.get("source_mode"),
                    details.get("windows_attributes"),
                    details.get("owner_name"),
                    details.get("owner_sid"),
                    details.get("security_descriptor"),
                    json.dumps(alternate_streams, ensure_ascii=False, sort_keys=True),
                    details.get("metadata_state", "legacy"),
                    details.get("metadata_error"),
                ),
            )
            db.execute(
                """
                UPDATE blocks
                SET copied_files=copied_files+1, copied_bytes=copied_bytes+?
                WHERE id=?
                """,
                (size, block_id),
            )
            return int(cursor.lastrowid)

    def update_file_metadata(self, file_version_id: int, metadata: dict[str, Any]) -> None:
        self.update_file_metadata_batch([(file_version_id, metadata)])

    def update_file_metadata_batch(
        self, updates: list[tuple[int, dict[str, Any]]]
    ) -> None:
        if not updates:
            return
        with self.transaction() as db:
            for file_version_id, metadata in updates:
                cursor = db.execute(
                    """
                    UPDATE file_versions SET
                        created_ns=?, accessed_ns=?, source_mode=?, windows_attributes=?,
                        owner_name=?, owner_sid=?, security_descriptor=?, alternate_streams_json=?,
                        metadata_state=?, metadata_error=?
                    WHERE id=?
                    """,
                    (
                        metadata.get("created_ns"),
                        metadata.get("accessed_ns"),
                        metadata.get("source_mode"),
                        metadata.get("windows_attributes"),
                        metadata.get("owner_name"),
                        metadata.get("owner_sid"),
                        metadata.get("security_descriptor"),
                        json.dumps(
                            metadata.get("alternate_streams", []),
                            ensure_ascii=False,
                            sort_keys=True,
                        ),
                        metadata.get("metadata_state", "partial"),
                        metadata.get("metadata_error"),
                        file_version_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise CatalogError(f"Versione file non trovata: {file_version_id}")

    def browse_backup_children(self, library_id: str, parent_path: str = "") -> list[dict[str, Any]]:
        """Return immediate current children from the local catalog only."""
        self.get_library(library_id, include_retired=True)
        normalized_parent = parent_path.replace("\\", "/").strip("/")
        if normalized_parent in (".", "..") or any(
            part in ("", ".", "..") for part in normalized_parent.split("/") if normalized_parent
        ):
            raise ValidationError(f"Cartella catalogo non valida: {parent_path}")
        current_cte = """
            WITH latest AS (
                SELECT candidate.relative_path, MAX(candidate.id) AS max_id
                FROM file_versions candidate
                JOIN blocks candidate_block ON candidate_block.id=candidate.block_id
                WHERE candidate.library_id=?
                  AND candidate.visible=1
                  AND candidate_block.status='completed'
                GROUP BY candidate.relative_path
            ), current_files AS (
                SELECT fv.*
                FROM file_versions fv
                JOIN latest ON latest.max_id=fv.id
            )
        """
        prefix = normalized_parent + "/" if normalized_parent else ""
        escaped_prefix = (
            prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        parent_rows = self.connection.execute(
            current_cte
            + "SELECT DISTINCT parent_path FROM current_files "
              "WHERE parent_path LIKE ? ESCAPE '\\'",
            (library_id, escaped_prefix + "%"),
        )
        directory_names: set[str] = set()
        for row in parent_rows:
            directory_path = row["parent_path"]
            if not directory_path.startswith(prefix):
                continue
            remainder = directory_path[len(prefix):]
            if remainder:
                directory_names.add(remainder.split("/", 1)[0])

        result: list[dict[str, Any]] = [
            {
                "kind": "directory",
                "name": name,
                "library_id": library_id,
                "relative_path": f"{prefix}{name}",
            }
            for name in sorted(directory_names, key=str.casefold)
        ]
        file_rows = self.connection.execute(
            current_cte + """
                SELECT
                    fv.*, l.name AS library_name, b.status AS block_status,
                    t.cassette_number, t.volume_label, t.volume_serial,
                    1 AS is_current
                FROM current_files fv
                JOIN libraries l ON l.id=fv.library_id
                JOIN blocks b ON b.id=fv.block_id
                JOIN tapes t ON t.id=fv.tape_id
                WHERE fv.parent_path=?
                ORDER BY fv.file_name COLLATE NOCASE
            """,
            (library_id, normalized_parent),
        )
        for row in file_rows:
            item = dict(row)
            item["kind"] = "file"
            item["name"] = item["file_name"]
            try:
                item["alternate_streams"] = json.loads(item["alternate_streams_json"] or "[]")
            except (TypeError, ValueError, json.JSONDecodeError):
                item["alternate_streams"] = []
            result.append(item)
        return result

    def complete_block(self, block_id: str) -> None:
        self.complete_blocks([block_id])

    def complete_blocks(self, block_ids: list[str]) -> None:
        if not block_ids:
            return
        with self.transaction() as db:
            completed_at = utc_now()
            for block_id in block_ids:
                cursor = db.execute(
                    """
                    UPDATE blocks SET status='completed', completed_at=?, error=NULL
                    WHERE id=? AND status='copying'
                    """,
                    (completed_at, block_id),
                )
                if cursor.rowcount != 1:
                    raise CatalogError(f"Blocco non in stato copying: {block_id}")
                self._event(db, "block.complete", {"block_id": block_id})

    def fail_block(self, block_id: str, error: str) -> None:
        self.fail_blocks([block_id], error)

    def fail_blocks(self, block_ids: list[str], error: str) -> None:
        if not block_ids:
            return
        with self.transaction() as db:
            failed_at = utc_now()
            for block_id in block_ids:
                cursor = db.execute(
                    """
                    UPDATE blocks SET status='failed', completed_at=?, error=?
                    WHERE id=? AND status='copying'
                    """,
                    (failed_at, error[:4000], block_id),
                )
                if cursor.rowcount:
                    db.execute(
                        "UPDATE file_versions SET visible=0 WHERE block_id=?",
                        (block_id,),
                    )
                    self._event(
                        db, "block.fail", {"block_id": block_id, "error": error[:1000]}
                    )

    def list_blocks(self, library_id: str | None = None, include_forgotten: bool = False) -> list[sqlite3.Row]:
        clauses: list[str] = []
        params: list[Any] = []
        if library_id:
            clauses.append("library_id=?")
            params.append(library_id)
        if not include_forgotten:
            clauses.append("visible=1")
        query = "SELECT * FROM blocks"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY started_at DESC"
        return list(self.connection.execute(query, params))

    def forget_block(self, block_id: str) -> None:
        with self.transaction() as db:
            cursor = db.execute("UPDATE blocks SET visible=0 WHERE id=? AND visible=1", (block_id,))
            if cursor.rowcount != 1:
                raise CatalogError(f"Blocco visibile non trovato: {block_id}")
            db.execute("UPDATE file_versions SET visible=0 WHERE block_id=?", (block_id,))
            self._event(db, "block.forget", {"block_id": block_id, "tape_data_deleted": False})

    def restore_plan(self, library_id: str) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                """
                WITH latest AS (
                    SELECT candidate.relative_path, MAX(candidate.id) AS max_id
                    FROM file_versions candidate
                    JOIN blocks candidate_block ON candidate_block.id=candidate.block_id
                    WHERE candidate.library_id=?
                      AND candidate.visible=1
                      AND candidate_block.status='completed'
                    GROUP BY candidate.relative_path
                )
                SELECT fv.tape_id, COUNT(*) AS file_count, SUM(fv.size) AS total_bytes
                FROM file_versions fv
                JOIN latest ON latest.max_id=fv.id
                GROUP BY fv.tape_id
                ORDER BY MIN(fv.id)
                """,
                (library_id,),
            )
        )

    def library_tape_distribution(self, library_id: str) -> list[sqlite3.Row]:
        """Return the physical location of each current catalogued file."""
        return list(
            self.connection.execute(
                """
                WITH latest AS (
                    SELECT candidate.relative_path, MAX(candidate.id) AS max_id
                    FROM file_versions candidate
                    JOIN blocks candidate_block ON candidate_block.id=candidate.block_id
                    WHERE candidate.library_id=?
                      AND candidate.visible=1
                      AND candidate_block.status='completed'
                    GROUP BY candidate.relative_path
                )
                SELECT fv.tape_id, t.cassette_number,
                       COUNT(*) AS file_count, SUM(fv.size) AS total_bytes
                FROM file_versions fv
                JOIN latest ON latest.max_id=fv.id
                JOIN tapes t ON t.id=fv.tape_id
                GROUP BY fv.tape_id, t.cassette_number
                ORDER BY t.cassette_number COLLATE NOCASE, fv.tape_id COLLATE NOCASE
                """,
                (library_id,),
            )
        )

    def restore_files_for_tape(self, library_id: str, tape_id: str) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                """
                WITH latest AS (
                    SELECT candidate.relative_path, MAX(candidate.id) AS max_id
                    FROM file_versions candidate
                    JOIN blocks candidate_block ON candidate_block.id=candidate.block_id
                    WHERE candidate.library_id=?
                      AND candidate.visible=1
                      AND candidate_block.status='completed'
                    GROUP BY candidate.relative_path
                )
                SELECT fv.*
                FROM file_versions fv
                JOIN latest ON latest.max_id=fv.id
                WHERE fv.tape_id=?
                ORDER BY fv.relative_path COLLATE NOCASE
                """,
                (library_id, tape_id),
            )
        )

    def block_file_versions(self, block_id: str) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT * FROM file_versions WHERE block_id=? ORDER BY id", (block_id,)
            )
        )

    def search_files(
        self,
        query: str,
        library_id: str | None = None,
        include_history: bool = False,
        limit: int = 500,
    ) -> list[sqlite3.Row]:
        if not 1 <= limit <= 5000:
            raise ValidationError("Il limite della ricerca deve essere compreso tra 1 e 5000")
        params: list[Any] = [query.strip()]
        clauses = ["instr(lower(fv.relative_path), lower(?)) > 0"]
        if library_id:
            clauses.append("fv.library_id=?")
            params.append(library_id)

        if include_history:
            current_expression = """
                CASE WHEN fv.id = (
                    SELECT MAX(current.id)
                    FROM file_versions current
                    JOIN blocks current_block ON current_block.id=current.block_id
                    WHERE current.library_id=fv.library_id
                      AND current.relative_path=fv.relative_path
                      AND current.visible=1
                      AND current_block.status='completed'
                ) THEN 1 ELSE 0 END
            """
            join_latest = ""
        else:
            current_expression = "1"
            join_latest = """
                JOIN (
                    SELECT candidate.library_id, candidate.relative_path,
                           MAX(candidate.id) AS max_id
                    FROM file_versions candidate
                    JOIN blocks candidate_block ON candidate_block.id=candidate.block_id
                    WHERE candidate.visible=1
                      AND candidate_block.status='completed'
                    GROUP BY candidate.library_id, candidate.relative_path
                ) latest ON latest.max_id=fv.id
            """

        clauses.append("b.status='completed'")

        sql = f"""
            SELECT
                fv.id,
                fv.library_id,
                l.name AS library_name,
                fv.relative_path,
                fv.parent_path,
                fv.file_name,
                fv.tape_relative_path,
                fv.size,
                fv.mtime_ns,
                fv.created_ns,
                fv.accessed_ns,
                fv.source_mode,
                fv.windows_attributes,
                fv.owner_name,
                fv.owner_sid,
                fv.security_descriptor,
                fv.alternate_streams_json,
                fv.metadata_state,
                fv.metadata_error,
                fv.sha256,
                fv.copied_at,
                fv.visible,
                fv.block_id,
                b.status AS block_status,
                fv.tape_id,
                t.cassette_number,
                t.volume_label,
                t.volume_serial,
                ({current_expression}) AS is_current
            FROM file_versions fv
            {join_latest}
            JOIN libraries l ON l.id=fv.library_id
            JOIN blocks b ON b.id=fv.block_id
            JOIN tapes t ON t.id=fv.tape_id
            WHERE {' AND '.join(clauses)}
            ORDER BY is_current DESC, fv.copied_at DESC, fv.id DESC
            LIMIT ?
        """
        params.append(limit)
        return list(self.connection.execute(sql, params))

    def create_automatic_job(
        self,
        job_id: str,
        library_id: str,
        device_name: str,
        mount_path: str,
        cassettes: list[tuple[str, str, int, int]],
        library_ids: list[str] | None = None,
        force_format: bool = False,
        media_key: str = "LTO-6",
        allow_registered_reuse: bool = False,
    ) -> None:
        validate_id(job_id, "ID job")
        ordered_library_ids: list[str] = []
        seen_library_ids: set[str] = set()
        for candidate in [library_id, *(library_ids or [])]:
            if candidate.casefold() in seen_library_ids:
                continue
            self.get_library(candidate)
            ordered_library_ids.append(candidate)
            seen_library_ids.add(candidate.casefold())
        if not cassettes:
            raise ValidationError("Il job automatico richiede almeno una cassetta")
        now = utc_now()
        try:
            with self.transaction() as db:
                for selected_library_id in ordered_library_ids:
                    active_job = db.execute(
                        """
                        SELECT aj.id
                        FROM automatic_jobs aj
                        JOIN automatic_job_libraries ajl ON ajl.job_id=aj.id
                        WHERE ajl.library_id=? COLLATE NOCASE
                          AND aj.status NOT IN ('completed', 'failed')
                        LIMIT 1
                        """,
                        (selected_library_id,),
                    ).fetchone()
                    if active_job:
                        raise CatalogError(
                            f"La libreria {selected_library_id} ha gia il job non concluso "
                            f"{active_job['id']}"
                        )
                for physical_label, _serial, _files, _bytes in cassettes:
                    queued = db.execute(
                        """
                        SELECT ac.job_id
                        FROM automatic_cassettes ac
                        WHERE ac.physical_label=? COLLATE NOCASE
                          AND ac.status != 'completed'
                        LIMIT 1
                        """,
                        (physical_label,),
                    ).fetchone()
                    if queued:
                        raise CatalogError(
                            f"La cassetta {physical_label} e gia assegnata al job "
                            f"{queued['job_id']}"
                        )
                    registered = db.execute(
                        "SELECT id FROM tapes WHERE cassette_number=? COLLATE NOCASE OR id=? COLLATE NOCASE",
                        (physical_label, physical_label),
                    ).fetchone()
                    if registered and not allow_registered_reuse:
                        raise CatalogError(
                            f"La cassetta {physical_label} e gia registrata come {registered['id']}; "
                            "non viene riformattata per proteggere i backup catalogati"
                        )
                db.execute(
                    """
                    INSERT INTO automatic_jobs(
                        id, display_name, media_key, library_id, device_name, mount_path, status,
                        total_cassettes, destructive_confirmed_at, force_format, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?, 'planned', ?, ?, ?, ?)
                    """,
                    (
                        job_id, job_id, media_key, library_id, device_name, mount_path, len(cassettes), now,
                        int(force_format), now,
                    ),
                )
                db.executemany(
                    """
                    INSERT INTO automatic_cassettes(
                        job_id, sequence, physical_label, tape_serial, status,
                        planned_files, planned_bytes, reuse_registered
                    ) VALUES(?, ?, ?, ?, 'pending', ?, ?, ?)
                    """,
                    [
                        (
                            job_id, sequence, physical_label, tape_serial, files, size,
                            int(allow_registered_reuse),
                        )
                        for sequence, (physical_label, tape_serial, files, size) in enumerate(cassettes, 1)
                    ],
                )
                db.executemany(
                    """
                    INSERT INTO automatic_job_libraries(job_id, library_id, sequence)
                    VALUES(?, ?, ?)
                    """,
                    [
                        (job_id, selected_library_id, sequence)
                        for sequence, selected_library_id in enumerate(ordered_library_ids, 1)
                    ],
                )
                self._event(
                    db,
                    "automatic_job.create",
                    {
                        "job_id": job_id,
                        "library_id": library_id,
                        "library_ids": ordered_library_ids,
                        "device_name": device_name,
                        "mount_path": mount_path,
                        "force_format": force_format,
                        "media_key": media_key,
                        "allow_registered_reuse": allow_registered_reuse,
                        "labels": [row[0] for row in cassettes],
                    },
                )
        except sqlite3.IntegrityError as exc:
            raise CatalogError(f"Job automatico o etichetta duplicata: {job_id}") from exc

    def get_automatic_job(self, job_id: str) -> sqlite3.Row:
        row = self.connection.execute("SELECT * FROM automatic_jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise CatalogError(f"Job automatico non trovato: {job_id}")
        return row

    def rename_automatic_job(self, job_id: str, display_name: str) -> None:
        normalized = display_name.strip()
        if not normalized:
            raise ValidationError("Il nome del job e obbligatorio")
        if len(normalized) > 120:
            raise ValidationError("Il nome del job non puo superare 120 caratteri")
        if any(ord(character) < 32 for character in normalized):
            raise ValidationError("Il nome del job contiene caratteri di controllo")
        with self.transaction() as db:
            job = db.execute(
                "SELECT display_name FROM automatic_jobs WHERE id=?", (job_id,)
            ).fetchone()
            if job is None:
                raise CatalogError(f"Job automatico non trovato: {job_id}")
            db.execute(
                "UPDATE automatic_jobs SET display_name=? WHERE id=?",
                (normalized, job_id),
            )
            self._event(
                db,
                "automatic_job.rename",
                {"job_id": job_id, "old_name": job["display_name"], "new_name": normalized},
            )

    def delete_automatic_job(self, job_id: str) -> dict:
        """Delete scheduler state while preserving every catalogued tape and backup block."""

        with self.transaction() as db:
            job = db.execute(
                "SELECT * FROM automatic_jobs WHERE id=?", (job_id,)
            ).fetchone()
            if job is None:
                raise CatalogError(f"Job automatico non trovato: {job_id}")
            cassettes = list(
                db.execute(
                    "SELECT sequence, block_id FROM automatic_cassettes "
                    "WHERE job_id=? ORDER BY sequence",
                    (job_id,),
                )
            )
            library_count = int(
                db.execute(
                    "SELECT COUNT(*) FROM automatic_job_libraries WHERE job_id=?",
                    (job_id,),
                ).fetchone()[0]
            )
            failed_at = utc_now()
            failed_incomplete_blocks = 0
            for block_id in dict.fromkeys(
                row["block_id"] for row in cassettes if row["block_id"]
            ):
                cursor = db.execute(
                    "UPDATE blocks SET status='failed', completed_at=?, error=? "
                    "WHERE id=? AND status='copying'",
                    (
                        failed_at,
                        "Job eliminato dall'operatore prima del completamento",
                        block_id,
                    ),
                )
                if cursor.rowcount:
                    failed_incomplete_blocks += 1
                    db.execute(
                        "UPDATE file_versions SET visible=0 WHERE block_id=?",
                        (block_id,),
                    )
            db.execute("DELETE FROM automatic_jobs WHERE id=?", (job_id,))
            result = {
                "id": job["id"],
                "display_name": job["display_name"],
                "deleted_cassettes": len(cassettes),
                "deleted_library_links": library_count,
                "failed_incomplete_blocks": failed_incomplete_blocks,
            }
            self._event(
                db,
                "automatic_job.delete",
                {
                    **result,
                    "tapes_deleted": 0,
                    "blocks_deleted": 0,
                    "tape_data_deleted": False,
                },
            )
            return result

    def append_automatic_cassettes(
        self,
        job_id: str,
        cassettes: list[tuple[str, str, int, int]],
        force_format: bool | None = None,
        *,
        allow_active: bool = False,
        allow_registered_reuse: bool = False,
    ) -> None:
        if not cassettes:
            raise ValidationError("Indicare almeno una nuova cassetta")
        now = utc_now()
        try:
            with self.transaction() as db:
                job = db.execute(
                    "SELECT * FROM automatic_jobs WHERE id=?", (job_id,)
                ).fetchone()
                if job is None:
                    raise CatalogError(f"Job automatico non trovato: {job_id}")
                allowed_statuses = (
                    {"completed", "failed", "planned", "paused", "waiting_media"}
                    if allow_active else {"completed", "failed"}
                )
                if job["status"] not in allowed_statuses:
                    raise ValidationError(
                        "Le cassette si possono aggiungere solo a un job concluso o in pausa sicura"
                    )
                unfinished = db.execute(
                    "SELECT sequence FROM automatic_cassettes "
                    "WHERE job_id=? AND status<>'completed' "
                    "AND NOT(status='pending' AND planned_files=0 AND planned_bytes=0) "
                    "ORDER BY sequence LIMIT 1",
                    (job_id,),
                ).fetchone()
                if unfinished and not allow_active:
                    raise ValidationError(
                        f"La cassetta {unfinished['sequence']} non e completata; "
                        "risolvere prima la coda esistente"
                    )
                active_job = db.execute(
                    "SELECT id FROM automatic_jobs WHERE device_name=? COLLATE NOCASE "
                    "AND id<>? COLLATE NOCASE AND status NOT IN ('completed', 'failed') LIMIT 1",
                    (job["device_name"], job_id),
                ).fetchone()
                if active_job:
                    raise CatalogError(
                        f"Il drive {job['device_name']} ha gia il job non concluso {active_job['id']}"
                    )
                for physical_label, tape_serial, _files, _bytes in cassettes:
                    queued = db.execute(
                        "SELECT sequence FROM automatic_cassettes "
                        "WHERE job_id=? AND (physical_label=? COLLATE NOCASE OR tape_serial=? COLLATE NOCASE)",
                        (job_id, physical_label, tape_serial),
                    ).fetchone()
                    if queued:
                        raise CatalogError(
                            f"La cassetta {physical_label} e gia presente nella sequenza {queued['sequence']}"
                        )
                    registered = db.execute(
                        "SELECT id FROM tapes WHERE cassette_number=? COLLATE NOCASE OR id=? COLLATE NOCASE",
                        (physical_label, physical_label),
                    ).fetchone()
                    if registered and not allow_registered_reuse:
                        raise CatalogError(
                            f"La cassetta {physical_label} e gia registrata come {registered['id']}; "
                            "non viene riformattata per proteggere i backup catalogati"
                        )
                last_sequence = int(
                    db.execute(
                        "SELECT COALESCE(MAX(sequence), 0) FROM automatic_cassettes WHERE job_id=?",
                        (job_id,),
                    ).fetchone()[0]
                )
                db.executemany(
                    """
                    INSERT INTO automatic_cassettes(
                        job_id, sequence, physical_label, tape_serial, status,
                        planned_files, planned_bytes, reuse_registered
                    ) VALUES(?, ?, ?, ?, 'pending', ?, ?, ?)
                    """,
                    [
                        (
                            job_id, last_sequence + offset, physical_label, tape_serial,
                            files, size, int(allow_registered_reuse),
                        )
                        for offset, (physical_label, tape_serial, files, size)
                        in enumerate(cassettes, 1)
                    ],
                )
                total = last_sequence + len(cassettes)
                db.execute(
                    """
                    UPDATE automatic_jobs
                    SET status='planned', total_cassettes=?, completed_at=NULL,
                        last_error=NULL, destructive_confirmed_at=?,
                        force_format=COALESCE(?, force_format)
                    WHERE id=?
                    """,
                    (total, now, int(force_format) if force_format is not None else None, job_id),
                )
                self._event(
                    db,
                    "automatic_job.extend",
                    {
                        "job_id": job_id,
                        "first_sequence": last_sequence + 1,
                        "total_cassettes": total,
                        "labels": [row[0] for row in cassettes],
                        "force_format": force_format,
                        "active_queue_preserved": allow_active,
                        "allow_registered_reuse": allow_registered_reuse,
                    },
                )
        except sqlite3.IntegrityError as exc:
            raise CatalogError(f"Etichetta duplicata nel job automatico {job_id}") from exc

    def commit_registered_tape_reformat(self, job_id: str, sequence: int) -> dict[str, int]:
        """Invalidate catalog records only after an authorized format has succeeded."""

        with self.transaction() as db:
            cassette = db.execute(
                "SELECT * FROM automatic_cassettes WHERE job_id=? AND sequence=?",
                (job_id, sequence),
            ).fetchone()
            if cassette is None:
                raise CatalogError(
                    f"Cassetta automatica non trovata: {job_id} sequenza {sequence}"
                )
            if not bool(cassette["reuse_registered"]):
                raise CatalogError(
                    f"La riformattazione della cassetta {cassette['physical_label']} "
                    "non e stata autorizzata"
                )
            if str(cassette["operation"] or "format") != "format":
                raise CatalogError(
                    "Una cassetta registrata si puo invalidare solo dopo la formattazione"
                )

            tapes = list(
                db.execute(
                    "SELECT * FROM tapes WHERE cassette_number=? COLLATE NOCASE "
                    "OR id=? COLLATE NOCASE",
                    (cassette["physical_label"], cassette["physical_label"]),
                )
            )
            if not tapes:
                return {"tapes": 0, "blocks": 0, "files": 0, "jobs": 0}
            if len(tapes) != 1:
                raise CatalogError(
                    f"La cassetta {cassette['physical_label']} identifica piu supporti nel catalogo"
                )

            tape = tapes[0]
            tape_id = str(tape["id"])
            cassette_number = str(tape["cassette_number"])
            affected = list(
                db.execute(
                    """
                    SELECT DISTINCT job_id
                    FROM automatic_cassettes
                    WHERE NOT(job_id=? AND sequence=?)
                      AND (
                        tape_id=? COLLATE NOCASE
                        OR physical_label=? COLLATE NOCASE
                        OR physical_label=? COLLATE NOCASE
                      )
                    """,
                    (job_id, sequence, tape_id, cassette_number, tape_id),
                )
            )
            affected_job_ids = [str(row["job_id"]) for row in affected]
            reason = (
                f"Dati invalidati: cassetta {cassette_number} riformattata "
                f"dal job {job_id}"
            )
            db.execute(
                """
                UPDATE automatic_cassettes
                SET status='failed', tape_id=NULL, block_id=NULL,
                    copied_files=0, copied_bytes=0, error=?
                WHERE NOT(job_id=? AND sequence=?)
                  AND (
                    tape_id=? COLLATE NOCASE
                    OR physical_label=? COLLATE NOCASE
                    OR physical_label=? COLLATE NOCASE
                  )
                """,
                (reason, job_id, sequence, tape_id, cassette_number, tape_id),
            )
            if affected_job_ids:
                placeholders = ", ".join("?" for _ in affected_job_ids)
                db.execute(
                    f"UPDATE automatic_jobs SET status='failed', completed_at=NULL, "
                    f"last_error=? WHERE id IN ({placeholders})",
                    (reason, *affected_job_ids),
                )

            file_count = int(
                db.execute(
                    "SELECT COUNT(*) FROM file_versions WHERE tape_id=? COLLATE NOCASE",
                    (tape_id,),
                ).fetchone()[0]
            )
            block_count = int(
                db.execute(
                    "SELECT COUNT(*) FROM blocks WHERE tape_id=? COLLATE NOCASE",
                    (tape_id,),
                ).fetchone()[0]
            )
            db.execute("DELETE FROM file_versions WHERE tape_id=? COLLATE NOCASE", (tape_id,))
            db.execute("DELETE FROM blocks WHERE tape_id=? COLLATE NOCASE", (tape_id,))
            db.execute("DELETE FROM tapes WHERE id=? COLLATE NOCASE", (tape_id,))
            result = {
                "tapes": 1,
                "blocks": block_count,
                "files": file_count,
                "jobs": len(affected_job_ids),
            }
            self._event(
                db,
                "tape.reformat.catalog_invalidated",
                {
                    "job_id": job_id,
                    "sequence": sequence,
                    "physical_label": cassette["physical_label"],
                    "tape_id": tape_id,
                    **result,
                },
            )
            return result

    def list_automatic_jobs(self) -> list[sqlite3.Row]:
        return list(self.connection.execute("SELECT * FROM automatic_jobs ORDER BY created_at DESC"))

    def list_automatic_cassettes(self, job_id: str) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT * FROM automatic_cassettes WHERE job_id=? ORDER BY sequence", (job_id,)
            )
        )

    def replace_automatic_cassette_manifest(
        self,
        job_id: str,
        sequence: int,
        items: list[tuple[str, str, int, int]],
    ) -> None:
        """Atomically freeze the exact paths assigned to one cassette."""

        normalized: list[tuple[str, str, int, int]] = []
        seen: set[tuple[str, str]] = set()
        for library_id, relative_path, size, mtime_ns in items:
            path = str(PurePosixPath(relative_path.replace("\\", "/"))).strip("/")
            if not path or path == "." or PurePosixPath(path).is_absolute():
                raise ValidationError(f"Percorso manifest non valido: {relative_path}")
            key = (library_id.casefold(), path.casefold())
            if key in seen:
                raise ValidationError(
                    f"Percorso duplicato nel manifest: {library_id}/{path}"
                )
            if int(size) < 0 or int(mtime_ns) < 0:
                raise ValidationError(f"Metadati manifest non validi: {library_id}/{path}")
            seen.add(key)
            normalized.append((library_id, path, int(size), int(mtime_ns)))

        with self.transaction() as db:
            cassette = db.execute(
                "SELECT planned_files, planned_bytes FROM automatic_cassettes "
                "WHERE job_id=? AND sequence=?",
                (job_id, int(sequence)),
            ).fetchone()
            if cassette is None:
                raise CatalogError(f"Cassetta {sequence} non trovata nel job {job_id}")
            if normalized and (
                len(normalized) != int(cassette["planned_files"])
                or sum(row[2] for row in normalized) != int(cassette["planned_bytes"])
            ):
                raise ValidationError(
                    f"Il manifest della cassetta {sequence} non coincide con il piano aggregato"
                )
            db.execute(
                "DELETE FROM automatic_cassette_items WHERE job_id=? AND sequence=?",
                (job_id, int(sequence)),
            )
            db.executemany(
                "INSERT INTO automatic_cassette_items("
                "job_id, sequence, item_sequence, library_id, relative_path, size, mtime_ns"
                ") VALUES(?, ?, ?, ?, ?, ?, ?)",
                [
                    (job_id, int(sequence), index, library_id, path, size, mtime_ns)
                    for index, (library_id, path, size, mtime_ns)
                    in enumerate(normalized, 1)
                ],
            )
            self._event(
                db,
                "automatic_cassette.manifest",
                {
                    "job_id": job_id,
                    "sequence": int(sequence),
                    "files": len(normalized),
                    "bytes": sum(row[2] for row in normalized),
                },
            )

    def list_automatic_cassette_manifest(
        self, job_id: str, sequence: int
    ) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT * FROM automatic_cassette_items "
                "WHERE job_id=? AND sequence=? ORDER BY item_sequence",
                (job_id, int(sequence)),
            )
        )

    def list_pending_automatic_manifest(self, job_id: str) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT item.* FROM automatic_cassette_items item "
                "JOIN automatic_cassettes cassette "
                "ON cassette.job_id=item.job_id AND cassette.sequence=item.sequence "
                "WHERE item.job_id=? AND cassette.status<>'completed' "
                "ORDER BY item.sequence, item.item_sequence",
                (job_id,),
            )
        )

    def replace_automatic_pending_plan(
        self,
        job_id: str,
        assignments: list[tuple[int, list[tuple[str, str, int, int]]]],
    ) -> None:
        """Atomically freeze every not-yet-completed cassette of a legacy job."""

        assignment_map = {int(sequence): items for sequence, items in assignments}
        with self.transaction() as db:
            rows = list(
                db.execute(
                    "SELECT sequence FROM automatic_cassettes "
                    "WHERE job_id=? AND status<>'completed' ORDER BY sequence",
                    (job_id,),
                )
            )
            known = {int(row["sequence"]) for row in rows}
            if set(assignment_map) != known:
                raise ValidationError(
                    "Il piano persistente deve coprire tutte le cassette non completate"
                )
            db.execute(
                "DELETE FROM automatic_cassette_items WHERE job_id=? "
                "AND sequence IN (SELECT sequence FROM automatic_cassettes "
                "WHERE job_id=? AND status<>'completed')",
                (job_id, job_id),
            )
            inserted = 0
            total_bytes = 0
            for row in rows:
                sequence = int(row["sequence"])
                items = assignment_map[sequence]
                db.execute(
                    "UPDATE automatic_cassettes SET planned_files=?, planned_bytes=? "
                    "WHERE job_id=? AND sequence=?",
                    (len(items), sum(int(item[2]) for item in items), job_id, sequence),
                )
                for item_sequence, (library_id, path, size, mtime_ns) in enumerate(items, 1):
                    db.execute(
                        "INSERT INTO automatic_cassette_items("
                        "job_id, sequence, item_sequence, library_id, relative_path, size, mtime_ns"
                        ") VALUES(?, ?, ?, ?, ?, ?, ?)",
                        (
                            job_id, sequence, item_sequence, library_id,
                            path.replace("\\", "/").strip("/"), int(size), int(mtime_ns),
                        ),
                    )
                    inserted += 1
                    total_bytes += int(size)
            self._event(
                db,
                "automatic_job.manifest.freeze",
                {
                    "job_id": job_id,
                    "cassettes": len(rows),
                    "files": inserted,
                    "bytes": total_bytes,
                },
            )

    def list_automatic_job_libraries(self, job_id: str) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT * FROM automatic_job_libraries WHERE job_id=? ORDER BY sequence",
                (job_id,),
            )
        )

    def next_automatic_cassette(self, job_id: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM automatic_cassettes "
            "WHERE job_id=? AND status<>'completed' ORDER BY sequence LIMIT 1",
            (job_id,),
        ).fetchone()

    def completed_tape_bytes(self, tape_id: str) -> int:
        """Return committed payload bytes for an offline capacity estimate."""

        row = self.connection.execute(
            "SELECT COALESCE(SUM(copied_bytes), 0) FROM blocks "
            "WHERE tape_id=? AND status='completed'",
            (tape_id,),
        ).fetchone()
        return max(0, int(row[0]))

    def completed_tape_file_layout(self, tape_id: str) -> list[sqlite3.Row]:
        """Return every committed physical file and its block for capacity estimates."""
        return list(
            self.connection.execute(
                """
                SELECT fv.block_id, fv.size
                FROM file_versions fv
                JOIN blocks b ON b.id=fv.block_id
                WHERE fv.tape_id=? AND b.status='completed'
                ORDER BY fv.id
                """,
                (tape_id,),
            )
        )

    def activate_automatic_append(
        self,
        job_id: str,
        sequence: int,
        planned_files: int,
        planned_bytes: int,
    ) -> None:
        """Reuse a completed cassette for one non-destructive incremental cycle."""

        if planned_files <= 0 or planned_bytes <= 0:
            raise ValidationError("Il ciclo append richiede almeno un file e un byte")
        with self.transaction() as db:
            cassette = db.execute(
                "SELECT * FROM automatic_cassettes WHERE job_id=? AND sequence=?",
                (job_id, sequence),
            ).fetchone()
            if cassette is None:
                raise CatalogError(f"Cassetta {sequence} non trovata nel job {job_id}")
            if cassette["status"] != "completed" or not cassette["tape_id"]:
                raise ValidationError(
                    "Solo una cassetta completata e registrata puo essere riaperta in append"
                )
            tape = db.execute(
                "SELECT id FROM tapes WHERE id=? AND status='active'",
                (cassette["tape_id"],),
            ).fetchone()
            if tape is None:
                raise CatalogError(
                    f"Il nastro catalogato {cassette['tape_id']} non e disponibile per l'append"
                )
            db.execute(
                """
                UPDATE automatic_cassettes
                SET status='pending', operation='append', planned_files=?, planned_bytes=?,
                    copied_files=0, copied_bytes=0, block_id=NULL,
                    started_at=NULL, completed_at=NULL, error=NULL
                WHERE job_id=? AND sequence=?
                """,
                (planned_files, planned_bytes, job_id, sequence),
            )
            db.execute(
                """
                UPDATE automatic_jobs
                SET status='planned', current_sequence=?, completed_at=NULL, last_error=NULL
                WHERE id=?
                """,
                (sequence, job_id),
            )
            self._event(
                db,
                "automatic_job.append.activate",
                {
                    "job_id": job_id,
                    "sequence": sequence,
                    "physical_label": cassette["physical_label"],
                    "planned_files": planned_files,
                    "planned_bytes": planned_bytes,
                },
            )

    def activate_automatic_reserves(
        self,
        job_id: str,
        assignments: list[tuple[int, int]],
        *,
        current_sequence: int | None = None,
    ) -> None:
        if not assignments:
            return
        with self.transaction() as db:
            job = db.execute(
                "SELECT id FROM automatic_jobs WHERE id=?", (job_id,)
            ).fetchone()
            if job is None:
                raise CatalogError(f"Job automatico non trovato: {job_id}")
            reserves = list(
                db.execute(
                    "SELECT sequence FROM automatic_cassettes "
                    "WHERE job_id=? AND status='pending' "
                    "AND planned_files=0 AND planned_bytes=0 "
                    "ORDER BY sequence",
                    (job_id,),
                )
            )
            if len(assignments) > len(reserves):
                raise ValidationError(
                    f"Il job {job_id} non dispone di cassette di riserva sufficienti"
                )
            for reserve, (planned_files, planned_bytes) in zip(reserves, assignments):
                db.execute(
                    "UPDATE automatic_cassettes SET operation='format', "
                    "planned_files=?, planned_bytes=? "
                    "WHERE job_id=? AND sequence=?",
                    (planned_files, planned_bytes, job_id, reserve["sequence"]),
                )
            first_sequence = (
                int(current_sequence)
                if current_sequence is not None
                else int(reserves[0]["sequence"])
            )
            db.execute(
                "UPDATE automatic_jobs SET status='planned', current_sequence=?, "
                "completed_at=NULL, last_error=NULL WHERE id=?",
                (first_sequence, job_id),
            )
            self._event(
                db,
                "automatic_job.reserve.activate",
                {
                    "job_id": job_id,
                    "first_sequence": first_sequence,
                    "activated_cassettes": len(assignments),
                },
            )

    def reserve_remaining_automatic_cassettes(self, job_id: str, after_sequence: int) -> int:
        with self.transaction() as db:
            cursor = db.execute(
                "UPDATE automatic_cassettes SET planned_files=0, planned_bytes=0 "
                "WHERE job_id=? AND sequence>? AND status='pending'",
                (job_id, after_sequence),
            )
            released = max(0, cursor.rowcount)
            if released:
                self._event(
                    db,
                    "automatic_job.reserve.release",
                    {
                        "job_id": job_id,
                        "after_sequence": after_sequence,
                        "reserved_cassettes": released,
                    },
                )
            return released

    def update_automatic_job(
        self,
        job_id: str,
        status: str,
        *,
        current_sequence: int | None = None,
        error: str | None = None,
    ) -> None:
        allowed = {
            "planned", "waiting_media", "formatting", "mounting", "writing",
            "unmounting", "paused", "completed", "failed",
        }
        if status not in allowed:
            raise ValidationError(f"Stato job automatico non valido: {status}")
        now = utc_now()
        with self.transaction() as db:
            cursor = db.execute(
                """
                UPDATE automatic_jobs SET status=?,
                    current_sequence=COALESCE(?, current_sequence),
                    started_at=CASE WHEN started_at IS NULL AND ?<>'planned' THEN ? ELSE started_at END,
                    completed_at=CASE WHEN ?='completed' THEN ? ELSE completed_at END,
                    last_error=?
                WHERE id=?
                """,
                (status, current_sequence, status, now, status, now, error[:4000] if error else None, job_id),
            )
            if cursor.rowcount != 1:
                raise CatalogError(f"Job automatico non trovato: {job_id}")
            self._event(
                db,
                "automatic_job.state",
                {"job_id": job_id, "status": status, "sequence": current_sequence, "error": error},
            )

    def update_automatic_cassette(
        self,
        job_id: str,
        sequence: int,
        status: str,
        *,
        tape_id: str | None = None,
        block_id: str | None = None,
        copied_files: int | None = None,
        copied_bytes: int | None = None,
        error: str | None = None,
    ) -> None:
        allowed = {
            "pending", "waiting_media", "formatting", "mounting", "writing",
            "unmounting", "completed", "failed",
        }
        if status not in allowed:
            raise ValidationError(f"Stato cassetta automatico non valido: {status}")
        now = utc_now()
        with self.transaction() as db:
            cursor = db.execute(
                """
                UPDATE automatic_cassettes SET status=?,
                    tape_id=COALESCE(?, tape_id), block_id=COALESCE(?, block_id),
                    copied_files=COALESCE(?, copied_files), copied_bytes=COALESCE(?, copied_bytes),
                    started_at=CASE WHEN started_at IS NULL AND ?<>'pending' THEN ? ELSE started_at END,
                    completed_at=CASE WHEN ?='completed' THEN ? ELSE completed_at END,
                    error=?
                WHERE job_id=? AND sequence=?
                """,
                (
                    status, tape_id, block_id, copied_files, copied_bytes,
                    status, now, status, now, error[:4000] if error else None,
                    job_id, sequence,
                ),
            )
            if cursor.rowcount != 1:
                raise CatalogError(f"Cassetta {sequence} non trovata nel job {job_id}")
            if status == "completed":
                db.execute(
                    "DELETE FROM automatic_cassette_items WHERE job_id=? AND sequence=?",
                    (job_id, sequence),
                )
            self._event(
                db,
                "automatic_cassette.state",
                {"job_id": job_id, "sequence": sequence, "status": status, "error": error},
            )

    def reset_automatic_cassette(
        self,
        job_id: str,
        sequence: int,
        reason: str,
    ) -> dict[str, int]:
        """Discard one interrupted tape attempt so it can be reformatted from scratch."""

        with self.transaction() as db:
            cassette = db.execute(
                "SELECT * FROM automatic_cassettes WHERE job_id=? AND sequence=?",
                (job_id, sequence),
            ).fetchone()
            if cassette is None:
                raise CatalogError(f"Cassetta {sequence} non trovata nel job {job_id}")
            if cassette["status"] == "completed":
                raise ValidationError("Una cassetta completata non puo essere azzerata")

            if cassette["operation"] == "append":
                failed_at = utc_now()
                block_ids = [
                    value.strip()
                    for value in str(cassette["block_id"] or "").split(",")
                    if value.strip()
                ]
                for block_id in block_ids:
                    db.execute(
                        "UPDATE blocks SET status='failed', visible=0, completed_at=?, error=? "
                        "WHERE id=? AND status='copying'",
                        (failed_at, reason[:4000], block_id),
                    )
                    db.execute("UPDATE file_versions SET visible=0 WHERE block_id=?", (block_id,))
                db.execute(
                    """
                    UPDATE automatic_cassettes
                    SET status='pending', block_id=NULL, copied_files=0, copied_bytes=0,
                        started_at=NULL, completed_at=NULL, error=NULL
                    WHERE job_id=? AND sequence=?
                    """,
                    (job_id, sequence),
                )
                db.execute(
                    """
                    UPDATE automatic_jobs
                    SET status='paused', current_sequence=?, completed_at=NULL, last_error=NULL
                    WHERE id=?
                    """,
                    (sequence, job_id),
                )
                result = {"blocks": 0, "files": 0, "tapes": 0}
                self._event(
                    db,
                    "automatic_cassette.append.reset",
                    {
                        "job_id": job_id,
                        "sequence": sequence,
                        "physical_label": cassette["physical_label"],
                        "reason": reason[:1000],
                        "preserved_tape": cassette["tape_id"],
                    },
                )
                return result

            tape_id = cassette["tape_id"] or cassette["physical_label"]
            tape = db.execute("SELECT * FROM tapes WHERE id=?", (tape_id,)).fetchone()
            if tape is not None and (
                str(tape["cassette_number"]).casefold()
                != str(cassette["physical_label"]).casefold()
            ):
                raise CatalogError(
                    f"Il nastro {tape_id} non corrisponde alla cassetta "
                    f"{cassette['physical_label']}"
                )

            file_count = int(
                db.execute(
                    "SELECT COUNT(*) FROM file_versions WHERE tape_id=?", (tape_id,)
                ).fetchone()[0]
            )
            block_count = int(
                db.execute("SELECT COUNT(*) FROM blocks WHERE tape_id=?", (tape_id,)).fetchone()[0]
            )
            db.execute("DELETE FROM file_versions WHERE tape_id=?", (tape_id,))
            db.execute("DELETE FROM blocks WHERE tape_id=?", (tape_id,))
            tape_count = db.execute("DELETE FROM tapes WHERE id=?", (tape_id,)).rowcount
            db.execute(
                """
                UPDATE automatic_cassettes
                SET status='pending', tape_id=NULL, block_id=NULL,
                    copied_files=0, copied_bytes=0, started_at=NULL,
                    completed_at=NULL, error=NULL
                WHERE job_id=? AND sequence=?
                """,
                (job_id, sequence),
            )
            cursor = db.execute(
                """
                UPDATE automatic_jobs
                SET status='paused', current_sequence=?, completed_at=NULL, last_error=NULL
                WHERE id=?
                """,
                (sequence, job_id),
            )
            if cursor.rowcount != 1:
                raise CatalogError(f"Job automatico non trovato: {job_id}")
            result = {
                "blocks": block_count,
                "files": file_count,
                "tapes": max(0, int(tape_count)),
            }
            self._event(
                db,
                "automatic_cassette.reset",
                {
                    "job_id": job_id,
                    "sequence": sequence,
                    "physical_label": cassette["physical_label"],
                    "reason": reason[:1000],
                    **result,
                },
            )
            return result

    def event(self, action: str, payload: dict[str, Any]) -> None:
        with self.transaction() as db:
            self._event(db, action, payload)

    def export(self, *, include_events: bool = True) -> dict[str, Any]:
        tables = [
            "libraries", "tapes", "blocks", "file_versions",
            "automatic_jobs", "automatic_job_libraries", "automatic_cassettes",
        ]
        if include_events:
            tables.append("events")
        result: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "exported_at": utc_now(),
        }
        for table in tables:
            result[table] = [dict(row) for row in self.connection.execute(f"SELECT * FROM {table}")]
        return result

    @staticmethod
    def _event(db: sqlite3.Connection, action: str, payload: dict[str, Any]) -> None:
        db.execute(
            "INSERT INTO events(occurred_at, action, payload_json) VALUES(?, ?, ?)",
            (utc_now(), action, json.dumps(payload, ensure_ascii=False, sort_keys=True)),
        )
