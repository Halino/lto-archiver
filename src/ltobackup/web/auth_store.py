from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
from math import isfinite
import re
import secrets
import sqlite3
import time
import unicodedata
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.profiles import RFC_9106_LOW_MEMORY

from ltobackup.errors import ValidationError

from .security import (
    ReauthenticationRateLimiter,
    constant_time_matches,
    sanitize_audit_payload,
)

AUTH_SCHEMA_VERSION = 2
_PRIMARY_CATALOG = Path("/var/lib/lto-archiver/catalog.db")
_MINIMUM_PASSWORD_LENGTH = 14
_MAXIMUM_PASSWORD_BYTES = 1024
_REAUTHENTICATION_SECONDS = 600.0
_TOKEN_BYTES = 32
_PASSWORD_HASHER = PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY)
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ROLES = frozenset({"admin", "operator"})
_LIFECYCLES = frozenset({"active", "disabled", "retired"})
_CURRENT_SCHEMA_FINGERPRINT = (
    "b1f0b4cab853130980c56a3dcc95e202889f292b74c4068c191ce3216418e98a"
)
_LEGACY_SCHEMA_FINGERPRINTS = frozenset(
    {
        # bc1572b, before and after SessionManager first creates its table.
        "21db3f7f62b975943e25ca5d463eed0e5eac47ac7e390ea0a46edda5f072d636",
        "baa311703e896f57a77e15e9c987ccb1892a7fc4832dd74bfa8284d5891106e8",
        # Fresh ccd55b5 databases, before and after first session use.
        "8c39c2e7baeeb84ad093db655904a442dd0716a6d56427fdf46addd69d1ff6fd",
        "3c2202bd60bb1bdac342f72b038ed35f50fa93202903d29c606d0b8acfd3da33",
        # Live ccd55b5 session schema preserves CREATE INDEX line wrapping.
        "70e50cd992a99d2ab5e782a1239ef058568fae75250fa6e4f7b42ff03c6aa5f8",
        # bc1572b upgraded by ccd55b5 ALTERs; payload precedes audit context.
        "efc7e828601bd932ab8da88301b49d3c16378e1ba9038ef3f2bce9754b027001",
        "75f8081a952826bf4253ea98a9218deaac9eb6ce8386625bf2f8fa89a73f5376",
    }
)


@dataclass(frozen=True)
class AuditContext:
    request_id: str | None = None
    remote_address: str | None = None

    def __post_init__(self) -> None:
        if self.request_id is not None:
            request_id = self.request_id.strip()
            if not _REQUEST_ID.fullmatch(request_id):
                raise ValidationError("Invalid audit request identifier")
            object.__setattr__(self, "request_id", request_id)
        if self.remote_address is not None:
            try:
                address = ipaddress.ip_address(self.remote_address.strip())
            except ValueError as exc:
                raise ValidationError("Invalid audit remote address") from exc
            object.__setattr__(self, "remote_address", str(address))


@dataclass(frozen=True)
class User:
    id: int
    login_name: str
    role: str
    state: str = "active"
    credential_generation: int = 1
    created_at: float = field(default=0.0, compare=False)
    last_login_at: float | None = field(default=None, compare=False)

    @property
    def enabled(self) -> bool:
        return self.state == "active"


@dataclass(frozen=True)
class Session:
    cookie: str = field(repr=False)
    csrf_token: str = field(repr=False)
    user: User
    created_at: float
    idle_expires_at: float
    absolute_expires_at: float
    reauthenticated_at: float | None = field(default=None, repr=False)


@dataclass(frozen=True)
class SessionReauthenticationEvidence:
    """Server-derived daemon attestation without the browser session secret."""

    session_binding_sha256: str
    reauthenticated_at: float


@dataclass(frozen=True)
class MutationReceipt:
    action: str
    target_user_id: int | None
    credential_generation: int | None
    changed_at: float


@dataclass(frozen=True)
class RestoreReplacementAuthorizationReceipt:
    state: str
    capability: str | None = field(default=None, repr=False)
    expires_at: float | None = None
    authorization_id: str | None = None


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _canonical_fingerprint(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(b"lto-web-auth-idempotency-v1\0" + encoded).hexdigest()


def _canonical_schema_fingerprint(connection: sqlite3.Connection) -> str:
    """Fingerprint every schema invariant, preserving SQLite's exact SQL text."""

    objects = []
    tables: list[str] = []
    rows = connection.execute(
        """
        SELECT type, name, tbl_name, sql
        FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
        ORDER BY type, name
        """
    ).fetchall()
    for row in rows:
        object_type = str(row[0])
        name = str(row[1])
        if object_type == "table":
            tables.append(name)
        objects.append(
            {
                "type": object_type,
                "name": name,
                "table": str(row[2]),
                "sql": (
                    None
                    if row[3] is None
                    else str(row[3])
                ),
            }
        )
    table_details: dict[str, Any] = {}
    for table in sorted(tables):
        indexes = []
        for index_row in connection.execute(f"PRAGMA index_list({table})"):
            index_name = str(index_row[1])
            indexes.append(
                {
                    "name": index_name,
                    "unique": int(index_row[2]),
                    "origin": str(index_row[3]),
                    "partial": int(index_row[4]),
                    "columns": [
                        [
                            int(detail[0]),
                            int(detail[1]),
                            None if detail[2] is None else str(detail[2]),
                            int(detail[3]),
                            str(detail[4]),
                            int(detail[5]),
                        ]
                        for detail in connection.execute(
                            f"PRAGMA index_xinfo({index_name})"
                        )
                    ],
                }
            )
        table_details[table] = {
            "columns": [list(row) for row in connection.execute(f"PRAGMA table_info({table})")],
            "foreign_keys": [
                list(row)
                for row in connection.execute(f"PRAGMA foreign_key_list({table})")
            ],
            "indexes": sorted(indexes, key=lambda item: str(item["name"])),
        }
    payload = {"objects": objects, "tables": table_details}
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(b"lto-web-auth-schema-v1\0" + encoded).hexdigest()


class AuthStore:
    """Own the versioned WebUI-only auth database and account invariants."""

    def __init__(
        self,
        database: str | Path,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.database = Path(database).expanduser()
        if self.database.resolve(strict=False) == _PRIMARY_CATALOG:
            raise ValidationError("The WebUI database must be separate from the catalog")
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._initialize()
        self.database.chmod(0o600)
        self._dummy_hash = _PASSWORD_HASHER.hash(
            "unusable dummy password material for timing equalization"
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _application_tables(connection: sqlite3.Connection) -> set[str]:
        return {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }

    @staticmethod
    def _column_names(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
        return tuple(
            str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")
        )

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            tables = self._application_tables(connection)
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if not tables and version == 0:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    self._create_current_schema(connection)
                    connection.execute(f"PRAGMA user_version = {AUTH_SCHEMA_VERSION}")
                    self._validate_current_schema(connection)
                except BaseException:
                    connection.rollback()
                    raise
                connection.commit()
                return
            if version == 0:
                self._validate_legacy_schema(connection)
                self._migrate_legacy_schema(connection)
                return
            if version != AUTH_SCHEMA_VERSION:
                raise ValidationError("Unsupported authentication database version")
            self._validate_current_schema(connection)

    @staticmethod
    def _create_current_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE web_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login_name TEXT NOT NULL,
                normalized_login TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'operator')),
                lifecycle TEXT NOT NULL CHECK (
                    lifecycle IN ('active', 'disabled', 'retired')
                ),
                credential_generation INTEGER NOT NULL CHECK (
                    credential_generation >= 1
                ),
                created_at REAL NOT NULL,
                last_login_at REAL,
                retired_at REAL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE web_sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                credential_generation INTEGER NOT NULL,
                csrf_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                last_seen_at REAL NOT NULL,
                idle_expires_at REAL NOT NULL,
                absolute_expires_at REAL NOT NULL,
                revoked_at REAL,
                reauthenticated_at REAL,
                FOREIGN KEY (user_id) REFERENCES web_users(id)
            )
            """
        )
        connection.execute("CREATE INDEX web_sessions_user ON web_sessions(user_id)")
        connection.execute(
            """
            CREATE TABLE web_auth_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                action TEXT NOT NULL,
                actor_user_id INTEGER,
                target_user_id INTEGER,
                login_name TEXT,
                result TEXT NOT NULL,
                request_id TEXT,
                remote_address TEXT,
                payload_json TEXT NOT NULL,
                FOREIGN KEY (actor_user_id) REFERENCES web_users(id),
                FOREIGN KEY (target_user_id) REFERENCES web_users(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE web_idempotency (
                idempotency_key TEXT PRIMARY KEY,
                actor_user_id INTEGER,
                action TEXT NOT NULL,
                target_key TEXT NOT NULL,
                request_fingerprint TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                FOREIGN KEY (actor_user_id) REFERENCES web_users(id)
            )
            """
        )

    def _validate_legacy_schema(self, connection: sqlite3.Connection) -> None:
        fingerprint = _canonical_schema_fingerprint(connection)
        if fingerprint not in _LEGACY_SCHEMA_FINGERPRINTS:
            raise ValidationError("Unrecognized legacy authentication schema")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise ValidationError("Inconsistent legacy authentication database")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or str(integrity[0]) != "ok":
            raise ValidationError("Inconsistent legacy authentication database")

    def _migrate_legacy_schema(self, connection: sqlite3.Connection) -> None:
        tables = self._application_tables(connection)
        audit_columns = self._column_names(connection, "web_auth_audit")
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute("ALTER TABLE web_users RENAME TO web_users_legacy")
            connection.execute(
                "ALTER TABLE web_auth_audit RENAME TO web_auth_audit_legacy"
            )
            if "web_sessions" in tables:
                connection.execute(
                    "ALTER TABLE web_sessions RENAME TO web_sessions_legacy"
                )
                connection.execute("DROP INDEX web_sessions_user")
            self._create_current_schema(connection)
            connection.execute(
                """
                INSERT INTO web_users (
                    id, login_name, normalized_login, password_hash, role,
                    lifecycle, credential_generation, created_at, last_login_at,
                    retired_at
                )
                SELECT id, login_name, normalized_login, password_hash, 'admin',
                       'active', 1, created_at, last_login_at, NULL
                FROM web_users_legacy
                """
            )
            request_expression = (
                "request_id" if "request_id" in audit_columns else "NULL"
            )
            remote_expression = (
                "remote_address" if "remote_address" in audit_columns else "NULL"
            )
            connection.execute(
                f"""
                INSERT INTO web_auth_audit (
                    id, created_at, action, actor_user_id, target_user_id,
                    login_name, result, request_id, remote_address, payload_json
                )
                SELECT id, created_at, action, NULL, user_id, login_name, result,
                       {request_expression}, {remote_expression}, payload_json
                FROM web_auth_audit_legacy
                """
            )
            if "web_sessions" in tables:
                connection.execute(
                    """
                    INSERT INTO web_sessions (
                        token_hash, user_id, credential_generation, csrf_hash,
                        created_at, last_seen_at, idle_expires_at,
                        absolute_expires_at, revoked_at, reauthenticated_at
                    )
                    SELECT token_hash, user_id, 1, csrf_hash, created_at,
                           last_seen_at, idle_expires_at, absolute_expires_at,
                           revoked_at, NULL
                    FROM web_sessions_legacy
                    """
                )
            connection.execute("DROP TABLE web_auth_audit_legacy")
            if "web_sessions" in tables:
                connection.execute("DROP TABLE web_sessions_legacy")
            connection.execute("DROP TABLE web_users_legacy")
            connection.execute(f"PRAGMA user_version = {AUTH_SCHEMA_VERSION}")
            self._validate_current_schema(connection)
        except BaseException:
            connection.rollback()
            raise
        connection.commit()

    def _validate_current_schema(self, connection: sqlite3.Connection) -> None:
        if _canonical_schema_fingerprint(connection) != _CURRENT_SCHEMA_FINGERPRINT:
            raise ValidationError("Invalid authentication database fingerprint")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise ValidationError("Inconsistent authentication database")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or str(integrity[0]) != "ok":
            raise ValidationError("Inconsistent authentication database")

    @staticmethod
    def _normalize_login(login_name: str) -> tuple[str, str]:
        display_name = str(login_name).strip()
        if not display_name:
            raise ValidationError("Username is required")
        if len(display_name) > 128:
            raise ValidationError("Username is too long")
        return display_name, display_name.casefold()

    @staticmethod
    def _validate_password(password: str) -> None:
        if not isinstance(password, str) or len(password) < _MINIMUM_PASSWORD_LENGTH:
            raise ValidationError("Password must contain at least 14 characters")
        if len(password.encode("utf-8")) > _MAXIMUM_PASSWORD_BYTES:
            raise ValidationError("Password exceeds 1024 UTF-8 bytes")
        if any(unicodedata.category(character) == "Cc" for character in password):
            raise ValidationError("Password contains control characters")

    @staticmethod
    def _validate_role(role: str) -> str:
        if role not in _ROLES:
            raise ValidationError("Invalid WebUI role")
        return role

    @staticmethod
    def _validate_idempotency_key(value: str) -> str:
        key = str(value)
        if not _IDEMPOTENCY_KEY.fullmatch(key):
            raise ValidationError("Invalid idempotency key")
        return key

    @staticmethod
    def _user_from_row(row: sqlite3.Row | Mapping[str, Any]) -> User:
        return User(
            id=int(row["id"]),
            login_name=str(row["login_name"]),
            role=str(row["role"]),
            state=str(row["lifecycle"]),
            credential_generation=int(row["credential_generation"]),
            created_at=float(row["created_at"]),
            last_login_at=(
                None if row["last_login_at"] is None else float(row["last_login_at"])
            ),
        )

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        *,
        action: str,
        result: str,
        actor_user_id: int | None = None,
        target_user_id: int | None = None,
        user_id: int | None = None,
        login_name: str | None = None,
        payload: Mapping[str, Any] | None = None,
        audit_context: AuditContext | None = None,
    ) -> None:
        if target_user_id is None:
            target_user_id = user_id
        safe_payload = sanitize_audit_payload(dict(payload or {}))
        context = audit_context or AuditContext()
        connection.execute(
            """
            INSERT INTO web_auth_audit (
                created_at, action, actor_user_id, target_user_id, login_name,
                result, request_id, remote_address, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self._clock(),
                action,
                actor_user_id,
                target_user_id,
                login_name,
                result,
                context.request_id,
                context.remote_address,
                json.dumps(safe_payload, sort_keys=True, separators=(",", ":")),
            ),
        )

    def _append_rejected_audit(
        self,
        *,
        action: str,
        actor_user_id: int | None,
        target_user_id: int | None,
        result: str,
        audit_context: AuditContext | None,
    ) -> None:
        with closing(self._connect()) as connection:
            if (
                actor_user_id is not None
                and self._row_for_user(connection, actor_user_id) is None
            ):
                actor_user_id = None
            if (
                target_user_id is not None
                and self._row_for_user(connection, target_user_id) is None
            ):
                target_user_id = None
            self._append_audit(
                connection,
                action=action,
                result=result,
                actor_user_id=actor_user_id,
                target_user_id=target_user_id,
                audit_context=audit_context,
            )
            connection.commit()

    @staticmethod
    def _row_for_user(
        connection: sqlite3.Connection, user_id: int
    ) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM web_users WHERE id = ?", (user_id,)
        ).fetchone()

    def _require_admin(
        self, connection: sqlite3.Connection, actor_user_id: int | None
    ) -> sqlite3.Row:
        if actor_user_id is None:
            raise ValidationError("WebUI administrator required")
        row = self._row_for_user(connection, actor_user_id)
        if row is None or row["lifecycle"] != "active" or row["role"] != "admin":
            raise ValidationError("WebUI administrator required")
        return row

    def _idempotent_replay(
        self,
        connection: sqlite3.Connection,
        *,
        key: str,
        actor_user_id: int | None,
        action: str,
        target_key: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any] | None:
        fingerprint = _canonical_fingerprint(request)
        row = connection.execute(
            "SELECT * FROM web_idempotency WHERE idempotency_key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        if (
            row["actor_user_id"] != actor_user_id
            or str(row["action"]) != action
            or str(row["target_key"]) != target_key
            or str(row["request_fingerprint"]) != fingerprint
        ):
            raise ValidationError("Idempotency key conflict")
        return json.loads(str(row["receipt_json"]))

    def _record_idempotency(
        self,
        connection: sqlite3.Connection,
        *,
        key: str,
        actor_user_id: int | None,
        action: str,
        target_key: str,
        request: Mapping[str, Any],
        receipt: Mapping[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO web_idempotency (
                idempotency_key, actor_user_id, action, target_key,
                request_fingerprint, receipt_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key,
                actor_user_id,
                action,
                target_key,
                _canonical_fingerprint(request),
                json.dumps(dict(receipt), sort_keys=True, separators=(",", ":")),
                self._clock(),
            ),
        )

    @staticmethod
    def _restore_replacement_request(
        session_binding_sha256: str, run_id: str, item_sequence: int
    ) -> tuple[str, dict[str, object]]:
        if not re.fullmatch(r"[0-9a-f]{64}", session_binding_sha256):
            raise ValidationError("Invalid session binding")
        if not _IDEMPOTENCY_KEY.fullmatch(run_id) or not 1 <= item_sequence <= 200:
            raise ValidationError("Invalid restore replacement target")
        target_key = f"{run_id}:{item_sequence}"
        return target_key, {
            "run_id": run_id,
            "item_sequence": item_sequence,
            "session_binding_sha256": session_binding_sha256,
        }

    @staticmethod
    def _restore_replacement_receipt(
        value: Mapping[str, Any],
    ) -> RestoreReplacementAuthorizationReceipt:
        if not isinstance(value, Mapping):
            raise ValidationError("Invalid restore replacement receipt")
        state = value.get("state")
        if state == "pending":
            if set(value) != {
                "state",
                "capability",
                "expires_at",
                "session_binding_sha256",
            }:
                raise ValidationError("Invalid restore replacement receipt")
            capability = value.get("capability")
            expires_at = value.get("expires_at")
            session_binding = value.get("session_binding_sha256")
            if (
                not isinstance(capability, str)
                or not 32 <= len(capability) <= 1024
                or isinstance(expires_at, bool)
                or not isinstance(expires_at, (int, float))
                or not isfinite(float(expires_at))
                or not 0 < float(expires_at) <= 253_402_300_799
                or not isinstance(session_binding, str)
                or not re.fullmatch(r"[0-9a-f]{64}", session_binding)
            ):
                raise ValidationError("Invalid restore replacement receipt")
            return RestoreReplacementAuthorizationReceipt(
                state="pending",
                capability=capability,
                expires_at=float(expires_at),
            )
        if state == "complete":
            if set(value) != {"state", "authorization_id"}:
                raise ValidationError("Invalid restore replacement receipt")
            authorization_id = value.get("authorization_id")
            if (
                not isinstance(authorization_id, str)
                or not _IDEMPOTENCY_KEY.fullmatch(authorization_id)
                or "capability" in value
            ):
                raise ValidationError("Invalid restore replacement receipt")
            return RestoreReplacementAuthorizationReceipt(
                state="complete", authorization_id=authorization_id
            )
        if state == "expired":
            if set(value) != {"state", "reason"}:
                raise ValidationError("Invalid restore replacement receipt")
            reason = value.get("reason")
            if reason not in {"terminal_rejection", "session_invalid"} or "capability" in value:
                raise ValidationError("Invalid restore replacement receipt")
            return RestoreReplacementAuthorizationReceipt(state="expired")
        raise ValidationError("Invalid restore replacement receipt")

    def restore_replacement_authorization_receipt(
        self,
        *,
        actor_user_id: int,
        session_binding_sha256: str,
        run_id: str,
        item_sequence: int,
        idempotency_key: str,
    ) -> RestoreReplacementAuthorizationReceipt | None:
        key = self._validate_idempotency_key(idempotency_key)
        target_key, request = self._restore_replacement_request(
            session_binding_sha256, run_id, item_sequence
        )
        with closing(self._connect()) as connection:
            self._require_admin(connection, actor_user_id)
            try:
                receipt = self._idempotent_replay(
                    connection,
                    key=key,
                    actor_user_id=actor_user_id,
                    action="restore.replacement.authorize",
                    target_key=target_key,
                    request=request,
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ValidationError("Invalid restore replacement receipt") from exc
        return None if receipt is None else self._restore_replacement_receipt(receipt)

    def reserve_restore_replacement_authorization(
        self,
        *,
        actor_user_id: int,
        session_binding_sha256: str,
        run_id: str,
        item_sequence: int,
        idempotency_key: str,
        capability: str,
        expires_at: float,
    ) -> RestoreReplacementAuthorizationReceipt:
        key = self._validate_idempotency_key(idempotency_key)
        target_key, request = self._restore_replacement_request(
            session_binding_sha256, run_id, item_sequence
        )
        if (
            not isinstance(capability, str)
            or not 32 <= len(capability) <= 1024
            or isinstance(expires_at, bool)
            or not isinstance(expires_at, (int, float))
            or not isfinite(float(expires_at))
            or not 0 < float(expires_at) <= 253_402_300_799
        ):
            raise ValidationError("Invalid restore replacement capability")
        pending = {
            "state": "pending",
            "capability": capability,
            "expires_at": float(expires_at),
            "session_binding_sha256": session_binding_sha256,
        }
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_admin(connection, actor_user_id)
            receipt = self._idempotent_replay(
                connection,
                key=key,
                actor_user_id=actor_user_id,
                action="restore.replacement.authorize",
                target_key=target_key,
                request=request,
            )
            if receipt is None:
                self._record_idempotency(
                    connection,
                    key=key,
                    actor_user_id=actor_user_id,
                    action="restore.replacement.authorize",
                    target_key=target_key,
                    request=request,
                    receipt=pending,
                )
                receipt = pending
            connection.commit()
        return self._restore_replacement_receipt(receipt)

    def complete_restore_replacement_authorization(
        self,
        *,
        actor_user_id: int,
        session_binding_sha256: str,
        run_id: str,
        item_sequence: int,
        idempotency_key: str,
        authorization_id: str,
    ) -> RestoreReplacementAuthorizationReceipt:
        key = self._validate_idempotency_key(idempotency_key)
        target_key, request = self._restore_replacement_request(
            session_binding_sha256, run_id, item_sequence
        )
        if not _IDEMPOTENCY_KEY.fullmatch(authorization_id):
            raise ValidationError("Invalid restore replacement authorization")
        complete = {"state": "complete", "authorization_id": authorization_id}
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_admin(connection, actor_user_id)
            receipt = self._idempotent_replay(
                connection,
                key=key,
                actor_user_id=actor_user_id,
                action="restore.replacement.authorize",
                target_key=target_key,
                request=request,
            )
            if receipt is None:
                connection.rollback()
                raise ValidationError("Restore replacement receipt is missing")
            parsed = self._restore_replacement_receipt(receipt)
            if parsed.state == "complete":
                connection.rollback()
                if parsed.authorization_id != authorization_id:
                    raise ValidationError("Idempotency key conflict")
                return parsed
            if parsed.state != "pending":
                connection.rollback()
                raise ValidationError("Restore replacement authorization is terminal")
            connection.execute(
                "UPDATE web_idempotency SET receipt_json = ? WHERE idempotency_key = ?",
                (json.dumps(complete, sort_keys=True, separators=(",", ":")), key),
            )
            connection.commit()
        return self._restore_replacement_receipt(complete)

    @staticmethod
    def _scrub_restore_replacement_authorizations(
        connection: sqlite3.Connection,
        *,
        actor_user_id: int | None = None,
        session_binding_sha256: str | None = None,
    ) -> None:
        if session_binding_sha256 is not None and not re.fullmatch(
            r"[0-9a-f]{64}", session_binding_sha256
        ):
            raise ValidationError("Invalid session binding")
        query = "SELECT idempotency_key, receipt_json FROM web_idempotency WHERE action = ?"
        parameters: list[object] = ["restore.replacement.authorize"]
        if actor_user_id is not None:
            query += " AND actor_user_id = ?"
            parameters.append(actor_user_id)
        for row in connection.execute(query, parameters).fetchall():
            try:
                receipt = json.loads(str(row["receipt_json"]))
            except (json.JSONDecodeError, TypeError, ValueError):
                receipt = None
            if not isinstance(receipt, Mapping) or receipt.get("state") != "pending":
                continue
            if (
                session_binding_sha256 is not None
                and receipt.get("session_binding_sha256") != session_binding_sha256
            ):
                continue
            tombstone = {"state": "expired", "reason": "session_invalid"}
            connection.execute(
                "UPDATE web_idempotency SET receipt_json = ? WHERE idempotency_key = ?",
                (
                    json.dumps(tombstone, sort_keys=True, separators=(",", ":")),
                    str(row["idempotency_key"]),
                ),
            )

    def scrub_restore_replacement_authorizations_for_session(
        self, session_binding_sha256: str
    ) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._scrub_restore_replacement_authorizations(
                connection, session_binding_sha256=session_binding_sha256
            )
            connection.commit()

    @staticmethod
    def _receipt_from_json(value: Mapping[str, Any]) -> MutationReceipt:
        return MutationReceipt(
            action=str(value["action"]),
            target_user_id=(
                None
                if value.get("target_user_id") is None
                else int(value["target_user_id"])
            ),
            credential_generation=(
                None
                if value.get("credential_generation") is None
                else int(value["credential_generation"])
            ),
            changed_at=float(value["changed_at"]),
        )

    def create_admin(
        self,
        username: str,
        password: str,
        *,
        audit_context: AuditContext | None = None,
    ) -> User:
        return self._create_user(
            username,
            password,
            role="admin",
            actor_user_id=None,
            idempotency_key=secrets.token_hex(24),
            audit_context=audit_context,
            break_glass=True,
            action="admin.created",
        )

    def create_user(
        self,
        username: str,
        password: str,
        *,
        role: str,
        actor_user_id: int,
        idempotency_key: str,
        audit_context: AuditContext | None = None,
    ) -> User:
        return self._create_user(
            username,
            password,
            role=role,
            actor_user_id=actor_user_id,
            idempotency_key=idempotency_key,
            audit_context=audit_context,
            break_glass=False,
            action="account.created",
        )

    def _create_user(
        self,
        username: str,
        password: str,
        *,
        role: str,
        actor_user_id: int | None,
        idempotency_key: str,
        audit_context: AuditContext | None,
        break_glass: bool,
        action: str,
    ) -> User:
        try:
            display_name, normalized_login = self._normalize_login(username)
            role = self._validate_role(role)
            key = self._validate_idempotency_key(idempotency_key)
        except ValidationError:
            self._append_rejected_audit(
                action=action,
                actor_user_id=actor_user_id,
                target_user_id=None,
                result="rejected",
                audit_context=audit_context,
            )
            raise
        request = {"normalized_login": normalized_login, "role": role}
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                if not break_glass:
                    self._require_admin(connection, actor_user_id)
                replay = self._idempotent_replay(
                    connection,
                    key=key,
                    actor_user_id=actor_user_id,
                    action=action,
                    target_key=normalized_login,
                    request=request,
                )
                if replay is not None:
                    row = self._row_for_user(connection, int(replay["user_id"]))
                    if row is None:
                        raise ValidationError("Inconsistent idempotency receipt")
                    connection.rollback()
                    return self._user_from_row(row)
                self._validate_password(password)
                password_hash = _PASSWORD_HASHER.hash(password)
                created_at = self._clock()
                cursor = connection.execute(
                    """
                    INSERT INTO web_users (
                        login_name, normalized_login, password_hash, role,
                        lifecycle, credential_generation, created_at
                    ) VALUES (?, ?, ?, ?, 'active', 1, ?)
                    """,
                    (display_name, normalized_login, password_hash, role, created_at),
                )
                user_id = int(cursor.lastrowid)
                receipt = {"user_id": user_id}
                self._record_idempotency(
                    connection,
                    key=key,
                    actor_user_id=actor_user_id,
                    action=action,
                    target_key=normalized_login,
                    request=request,
                    receipt=receipt,
                )
                self._append_audit(
                    connection,
                    action=action,
                    result="success",
                    actor_user_id=actor_user_id,
                    target_user_id=user_id,
                    login_name=display_name,
                    payload={"role": role},
                    audit_context=audit_context,
                )
                connection.commit()
                return User(
                    user_id,
                    display_name,
                    role,
                    "active",
                    1,
                    created_at,
                    None,
                )
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                self._append_rejected_audit(
                    action=action,
                    actor_user_id=actor_user_id,
                    target_user_id=None,
                    result="rejected",
                    audit_context=audit_context,
                )
                raise ValidationError("Username already exists") from exc
            except ValidationError:
                connection.rollback()
                self._append_rejected_audit(
                    action=action,
                    actor_user_id=actor_user_id,
                    target_user_id=None,
                    result="rejected",
                    audit_context=audit_context,
                )
                raise

    def _dummy_verify(self, supplied_password: str) -> None:
        try:
            _PASSWORD_HASHER.verify(self._dummy_hash, supplied_password)
        except (VerificationError, InvalidHashError):
            pass

    def authenticate(
        self,
        login_name: str,
        supplied_password: str,
        *,
        audit_context: AuditContext | None = None,
    ) -> User | None:
        try:
            display_name, normalized_login = self._normalize_login(login_name)
        except ValidationError:
            display_name, normalized_login = "", ""
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM web_users WHERE normalized_login = ?",
                (normalized_login,),
            ).fetchone()
        if row is None:
            self._dummy_verify(supplied_password)
            self._append_authentication_failure(
                None, display_name, "invalid_credentials", audit_context
            )
            return None
        try:
            _PASSWORD_HASHER.verify(str(row["password_hash"]), supplied_password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            self._append_authentication_failure(
                int(row["id"]),
                str(row["login_name"]),
                "invalid_credentials",
                audit_context,
            )
            return None
        snapshot_hash = str(row["password_hash"])
        snapshot_generation = int(row["credential_generation"])
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._row_for_user(connection, int(row["id"]))
            if (
                current is None
                or current["lifecycle"] != "active"
                or str(current["password_hash"]) != snapshot_hash
                or int(current["credential_generation"]) != snapshot_generation
            ):
                connection.rollback()
                self._append_authentication_failure(
                    int(row["id"]),
                    str(row["login_name"]),
                    "authority_changed",
                    audit_context,
                )
                return None
            now = self._clock()
            replacement_hash = snapshot_hash
            if _PASSWORD_HASHER.check_needs_rehash(snapshot_hash):
                replacement_hash = _PASSWORD_HASHER.hash(supplied_password)
            connection.execute(
                "UPDATE web_users SET password_hash = ?, last_login_at = ? WHERE id = ?",
                (replacement_hash, now, int(row["id"])),
            )
            self._append_audit(
                connection,
                action="auth.succeeded",
                result="success",
                target_user_id=int(row["id"]),
                login_name=str(row["login_name"]),
                audit_context=audit_context,
            )
            connection.commit()
            refreshed = dict(current)
            refreshed["last_login_at"] = now
            return self._user_from_row(refreshed)

    def _append_authentication_failure(
        self,
        user_id: int | None,
        login_name: str,
        result: str,
        audit_context: AuditContext | None,
    ) -> None:
        with closing(self._connect()) as connection:
            self._append_audit(
                connection,
                action="auth.failed",
                result=result,
                target_user_id=user_id,
                login_name=login_name,
                audit_context=audit_context,
            )
            connection.commit()

    def list_users(self) -> list[User]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM web_users ORDER BY normalized_login"
            ).fetchall()
        return [self._user_from_row(row) for row in rows]

    def get_user(self, user_id: int) -> User | None:
        with closing(self._connect()) as connection:
            row = self._row_for_user(connection, user_id)
        return None if row is None else self._user_from_row(row)

    def get_user_by_login(self, login_name: str) -> User | None:
        _display, normalized = self._normalize_login(login_name)
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM web_users WHERE normalized_login = ?", (normalized,)
            ).fetchone()
        return None if row is None else self._user_from_row(row)

    def set_enabled(
        self,
        user_id: int,
        enabled: bool,
        *,
        audit_context: AuditContext | None = None,
    ) -> None:
        key = secrets.token_hex(24)
        if enabled:
            self.enable_user(
                actor_user_id=None,
                target_user_id=user_id,
                idempotency_key=key,
                audit_context=audit_context,
                allow_break_glass=True,
            )
        else:
            self.disable_user(
                actor_user_id=None,
                target_user_id=user_id,
                idempotency_key=key,
                audit_context=audit_context,
                allow_break_glass=True,
            )

    def disable_user(
        self,
        *,
        actor_user_id: int | None,
        target_user_id: int,
        idempotency_key: str,
        audit_context: AuditContext | None = None,
        allow_break_glass: bool = False,
    ) -> User:
        return self._change_lifecycle(
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            desired="disabled",
            idempotency_key=idempotency_key,
            audit_context=audit_context,
            allow_break_glass=allow_break_glass,
            reauthenticated_session=None,
        )

    def enable_user(
        self,
        *,
        actor_user_id: int | None,
        target_user_id: int,
        idempotency_key: str,
        audit_context: AuditContext | None = None,
        allow_break_glass: bool = False,
    ) -> User:
        return self._change_lifecycle(
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            desired="active",
            idempotency_key=idempotency_key,
            audit_context=audit_context,
            allow_break_glass=allow_break_glass,
            reauthenticated_session=None,
        )

    def retire_user(
        self,
        *,
        actor_user_id: int,
        target_user_id: int,
        reauthenticated_session: str,
        idempotency_key: str,
        audit_context: AuditContext | None = None,
    ) -> User:
        return self._change_lifecycle(
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            desired="retired",
            idempotency_key=idempotency_key,
            audit_context=audit_context,
            allow_break_glass=False,
            reauthenticated_session=reauthenticated_session,
        )

    def _change_lifecycle(
        self,
        *,
        actor_user_id: int | None,
        target_user_id: int,
        desired: str,
        idempotency_key: str,
        audit_context: AuditContext | None,
        allow_break_glass: bool,
        reauthenticated_session: str | None,
    ) -> User:
        if desired not in _LIFECYCLES:
            raise ValidationError("Invalid WebUI account state")
        action = {
            "active": "account.enabled",
            "disabled": "account.disabled",
            "retired": "account.retired",
        }[desired]
        try:
            key = self._validate_idempotency_key(idempotency_key)
        except ValidationError:
            self._append_rejected_audit(
                action=action,
                actor_user_id=actor_user_id,
                target_user_id=target_user_id,
                result="rejected",
                audit_context=audit_context,
            )
            raise
        request = {"lifecycle": desired}
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                if not allow_break_glass:
                    self._require_admin(connection, actor_user_id)
                replay = self._idempotent_replay(
                    connection,
                    key=key,
                    actor_user_id=actor_user_id,
                    action=action,
                    target_key=str(target_user_id),
                    request=request,
                )
                if replay is not None:
                    row = self._row_for_user(connection, target_user_id)
                    if row is None:
                        raise ValidationError("Inconsistent idempotency receipt")
                    connection.rollback()
                    return self._user_from_row(row)
                target = self._row_for_user(connection, target_user_id)
                if target is None:
                    raise ValidationError("WebUI user not found")
                if (
                    actor_user_id is not None
                    and target_user_id == actor_user_id
                    and desired != "active"
                ):
                    raise ValidationError("Action on your own account is not allowed")
                current = str(target["lifecycle"])
                allowed = {
                    ("active", "disabled"),
                    ("disabled", "active"),
                    ("active", "retired"),
                    ("disabled", "retired"),
                }
                if (current, desired) not in allowed:
                    raise ValidationError("Account state transition is not allowed")
                if desired == "retired" and not allow_break_glass:
                    assert actor_user_id is not None
                    self._require_recent_reauthentication(
                        connection, actor_user_id, reauthenticated_session
                    )
                if (
                    target["role"] == "admin"
                    and current == "active"
                    and desired != "active"
                    and self._active_admin_count(connection) <= 1
                ):
                    raise ValidationError("Cannot remove the last administrator")
                generation = int(target["credential_generation"])
                if desired in {"disabled", "retired"}:
                    generation += 1
                    self._revoke_sessions(connection, target_user_id)
                retired_at = self._clock() if desired == "retired" else None
                connection.execute(
                    "UPDATE web_users SET lifecycle = ?, credential_generation = ?, "
                    "retired_at = ? WHERE id = ?",
                    (desired, generation, retired_at, target_user_id),
                )
                self._record_idempotency(
                    connection,
                    key=key,
                    actor_user_id=actor_user_id,
                    action=action,
                    target_key=str(target_user_id),
                    request=request,
                    receipt={"user_id": target_user_id},
                )
                self._append_audit(
                    connection,
                    action=action,
                    result="success",
                    actor_user_id=actor_user_id,
                    target_user_id=target_user_id,
                    payload={"state": desired},
                    audit_context=audit_context,
                )
                row = self._row_for_user(connection, target_user_id)
                assert row is not None
                connection.commit()
                return self._user_from_row(row)
            except ValidationError:
                connection.rollback()
                self._append_rejected_audit(
                    action=action,
                    actor_user_id=actor_user_id,
                    target_user_id=target_user_id,
                    result="rejected",
                    audit_context=audit_context,
                )
                raise

    @staticmethod
    def _active_admin_count(connection: sqlite3.Connection) -> int:
        row = connection.execute(
            "SELECT COUNT(*) FROM web_users "
            "WHERE role = 'admin' AND lifecycle = 'active'"
        ).fetchone()
        assert row is not None
        return int(row[0])

    def _require_recent_reauthentication(
        self,
        connection: sqlite3.Connection,
        actor_user_id: int,
        raw_cookie: str | None,
    ) -> sqlite3.Row:
        if not raw_cookie:
            raise ValidationError("Administrator reauthentication required")
        row = connection.execute(
            """
            SELECT s.*, u.lifecycle, u.credential_generation AS user_generation
            FROM web_sessions AS s
            JOIN web_users AS u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.user_id = ?
            """,
            (_token_hash(raw_cookie), actor_user_id),
        ).fetchone()
        now = self._clock()
        if (
            row is None
            or row["revoked_at"] is not None
            or row["lifecycle"] != "active"
            or int(row["credential_generation"]) != int(row["user_generation"])
            or now >= float(row["idle_expires_at"])
            or now >= float(row["absolute_expires_at"])
            or row["reauthenticated_at"] is None
            or now > float(row["reauthenticated_at"]) + _REAUTHENTICATION_SECONDS
        ):
            raise ValidationError("Administrator reauthentication required")
        return row

    def _revoke_sessions(self, connection: sqlite3.Connection, user_id: int) -> None:
        connection.execute(
            "UPDATE web_sessions SET revoked_at = COALESCE(revoked_at, ?), "
            "reauthenticated_at = NULL WHERE user_id = ?",
            (self._clock(), user_id),
        )
        self._scrub_restore_replacement_authorizations(
            connection, actor_user_id=user_id
        )

    def set_role(
        self,
        *,
        actor_user_id: int,
        target_user_id: int,
        role: str,
        reauthenticated_session: str | None,
        idempotency_key: str,
        audit_context: AuditContext | None = None,
    ) -> User:
        action = "account.role_changed"
        try:
            role = self._validate_role(role)
            key = self._validate_idempotency_key(idempotency_key)
        except ValidationError:
            self._append_rejected_audit(
                action=action,
                actor_user_id=actor_user_id,
                target_user_id=target_user_id,
                result="rejected",
                audit_context=audit_context,
            )
            raise
        request = {"role": role}
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._require_admin(connection, actor_user_id)
                replay = self._idempotent_replay(
                    connection,
                    key=key,
                    actor_user_id=actor_user_id,
                    action=action,
                    target_key=str(target_user_id),
                    request=request,
                )
                if replay is not None:
                    row = self._row_for_user(connection, target_user_id)
                    if row is None:
                        raise ValidationError("Inconsistent idempotency receipt")
                    connection.rollback()
                    return self._user_from_row(row)
                target = self._row_for_user(connection, target_user_id)
                if target is None or target["lifecycle"] == "retired":
                    raise ValidationError("WebUI user unavailable")
                old_role = str(target["role"])
                if old_role == role:
                    raise ValidationError("Account role is unchanged")
                generation = int(target["credential_generation"])
                if old_role == "admin" and role == "operator":
                    self._require_recent_reauthentication(
                        connection, actor_user_id, reauthenticated_session
                    )
                    if (
                        target["lifecycle"] == "active"
                        and self._active_admin_count(connection) <= 1
                    ):
                        raise ValidationError("Cannot remove the last administrator")
                    generation += 1
                    self._revoke_sessions(connection, target_user_id)
                connection.execute(
                    "UPDATE web_users SET role = ?, credential_generation = ? WHERE id = ?",
                    (role, generation, target_user_id),
                )
                self._record_idempotency(
                    connection,
                    key=key,
                    actor_user_id=actor_user_id,
                    action=action,
                    target_key=str(target_user_id),
                    request=request,
                    receipt={"user_id": target_user_id},
                )
                self._append_audit(
                    connection,
                    action=action,
                    result="success",
                    actor_user_id=actor_user_id,
                    target_user_id=target_user_id,
                    payload={"role": role},
                    audit_context=audit_context,
                )
                row = self._row_for_user(connection, target_user_id)
                assert row is not None
                connection.commit()
                return self._user_from_row(row)
            except ValidationError:
                connection.rollback()
                self._append_rejected_audit(
                    action=action,
                    actor_user_id=actor_user_id,
                    target_user_id=target_user_id,
                    result="rejected",
                    audit_context=audit_context,
                )
                raise

    def change_password(
        self,
        *,
        user_id: int,
        current_password: str,
        new_password: str,
        idempotency_key: str,
        audit_context: AuditContext | None = None,
    ) -> MutationReceipt:
        return self._replace_password(
            actor_user_id=user_id,
            target_user_id=user_id,
            current_password=current_password,
            new_password=new_password,
            reauthenticated_session=None,
            idempotency_key=idempotency_key,
            audit_context=audit_context,
            break_glass=False,
            action="account.password_changed",
        )

    def reset_password(
        self,
        *,
        actor_user_id: int,
        target_user_id: int,
        new_password: str,
        reauthenticated_session: str,
        idempotency_key: str,
        audit_context: AuditContext | None = None,
    ) -> MutationReceipt:
        return self._replace_password(
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            current_password=None,
            new_password=new_password,
            reauthenticated_session=reauthenticated_session,
            idempotency_key=idempotency_key,
            audit_context=audit_context,
            break_glass=False,
            action="account.password_reset",
        )

    def reset_password_break_glass(
        self,
        *,
        target_user_id: int,
        new_password: str,
        idempotency_key: str,
        audit_context: AuditContext | None = None,
    ) -> MutationReceipt:
        return self._replace_password(
            actor_user_id=None,
            target_user_id=target_user_id,
            current_password=None,
            new_password=new_password,
            reauthenticated_session=None,
            idempotency_key=idempotency_key,
            audit_context=audit_context,
            break_glass=True,
            action="account.password_reset",
        )

    def _replace_password(
        self,
        *,
        actor_user_id: int | None,
        target_user_id: int,
        current_password: str | None,
        new_password: str,
        reauthenticated_session: str | None,
        idempotency_key: str,
        audit_context: AuditContext | None,
        break_glass: bool,
        action: str,
    ) -> MutationReceipt:
        try:
            key = self._validate_idempotency_key(idempotency_key)
        except ValidationError:
            self._append_rejected_audit(
                action=action,
                actor_user_id=actor_user_id,
                target_user_id=target_user_id,
                result="rejected",
                audit_context=audit_context,
            )
            raise
        request = {"credential_operation": action}
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                if (
                    not break_glass
                    and current_password is None
                    and actor_user_id == target_user_id
                ):
                    raise ValidationError(
                        "An administrative reset does not replace a personal password change"
                    )
                if not break_glass and actor_user_id != target_user_id:
                    self._require_admin(connection, actor_user_id)
                replay = self._idempotent_replay(
                    connection,
                    key=key,
                    actor_user_id=actor_user_id,
                    action=action,
                    target_key=str(target_user_id),
                    request=request,
                )
                if replay is not None:
                    connection.rollback()
                    return self._receipt_from_json(replay)
                if not break_glass and actor_user_id != target_user_id:
                    assert actor_user_id is not None
                    self._require_recent_reauthentication(
                        connection, actor_user_id, reauthenticated_session
                    )
                self._validate_password(new_password)
                replacement_hash = _PASSWORD_HASHER.hash(new_password)
                target = self._row_for_user(connection, target_user_id)
                if target is None or target["lifecycle"] == "retired":
                    raise ValidationError("WebUI user unavailable")
                if current_password is not None:
                    try:
                        _PASSWORD_HASHER.verify(
                            str(target["password_hash"]), current_password
                        )
                    except (
                        VerifyMismatchError,
                        VerificationError,
                        InvalidHashError,
                    ) as exc:
                        raise ValidationError("Invalid current password") from exc
                generation = int(target["credential_generation"]) + 1
                changed_at = self._clock()
                connection.execute(
                    "UPDATE web_users SET password_hash = ?, credential_generation = ? "
                    "WHERE id = ?",
                    (replacement_hash, generation, target_user_id),
                )
                self._revoke_sessions(connection, target_user_id)
                receipt_value = {
                    "action": action,
                    "target_user_id": target_user_id,
                    "credential_generation": generation,
                    "changed_at": changed_at,
                }
                self._record_idempotency(
                    connection,
                    key=key,
                    actor_user_id=actor_user_id,
                    action=action,
                    target_key=str(target_user_id),
                    request=request,
                    receipt=receipt_value,
                )
                self._append_audit(
                    connection,
                    action=action,
                    result="success",
                    actor_user_id=actor_user_id,
                    target_user_id=target_user_id,
                    audit_context=audit_context,
                )
                connection.commit()
                return self._receipt_from_json(receipt_value)
            except ValidationError:
                connection.rollback()
                self._append_rejected_audit(
                    action=action,
                    actor_user_id=actor_user_id,
                    target_user_id=target_user_id,
                    result="rejected",
                    audit_context=audit_context,
                )
                raise

    def revoke_user_sessions(
        self,
        *,
        actor_user_id: int | None,
        target_user_id: int,
        idempotency_key: str,
        audit_context: AuditContext | None = None,
        allow_break_glass: bool = False,
    ) -> MutationReceipt:
        action = "sessions.user_revoked"
        try:
            key = self._validate_idempotency_key(idempotency_key)
        except ValidationError:
            self._append_rejected_audit(
                action=action,
                actor_user_id=actor_user_id,
                target_user_id=target_user_id,
                result="rejected",
                audit_context=audit_context,
            )
            raise
        request = {"scope": "user"}
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                if not allow_break_glass and actor_user_id != target_user_id:
                    self._require_admin(connection, actor_user_id)
                replay = self._idempotent_replay(
                    connection,
                    key=key,
                    actor_user_id=actor_user_id,
                    action=action,
                    target_key=str(target_user_id),
                    request=request,
                )
                if replay is not None:
                    connection.rollback()
                    return self._receipt_from_json(replay)
                target = self._row_for_user(connection, target_user_id)
                if target is None or target["lifecycle"] == "retired":
                    raise ValidationError("WebUI user unavailable")
                generation = int(target["credential_generation"]) + 1
                changed_at = self._clock()
                connection.execute(
                    "UPDATE web_users SET credential_generation = ? WHERE id = ?",
                    (generation, target_user_id),
                )
                self._revoke_sessions(connection, target_user_id)
                receipt_value = {
                    "action": action,
                    "target_user_id": target_user_id,
                    "credential_generation": generation,
                    "changed_at": changed_at,
                }
                self._record_idempotency(
                    connection,
                    key=key,
                    actor_user_id=actor_user_id,
                    action=action,
                    target_key=str(target_user_id),
                    request=request,
                    receipt=receipt_value,
                )
                self._append_audit(
                    connection,
                    action=action,
                    result="success",
                    actor_user_id=actor_user_id,
                    target_user_id=target_user_id,
                    audit_context=audit_context,
                )
                connection.commit()
                return self._receipt_from_json(receipt_value)
            except ValidationError:
                connection.rollback()
                self._append_rejected_audit(
                    action=action,
                    actor_user_id=actor_user_id,
                    target_user_id=target_user_id,
                    result="rejected",
                    audit_context=audit_context,
                )
                raise

    def revoke_all_sessions(
        self,
        *,
        actor_user_id: int,
        reauthenticated_session: str,
        idempotency_key: str,
        audit_context: AuditContext | None = None,
    ) -> MutationReceipt:
        action = "sessions.all_revoked"
        try:
            key = self._validate_idempotency_key(idempotency_key)
        except ValidationError:
            self._append_rejected_audit(
                action=action,
                actor_user_id=actor_user_id,
                target_user_id=None,
                result="rejected",
                audit_context=audit_context,
            )
            raise
        request = {"scope": "all"}
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._require_admin(connection, actor_user_id)
                replay = self._idempotent_replay(
                    connection,
                    key=key,
                    actor_user_id=actor_user_id,
                    action=action,
                    target_key="all",
                    request=request,
                )
                if replay is not None:
                    connection.rollback()
                    return self._receipt_from_json(replay)
                self._require_recent_reauthentication(
                    connection, actor_user_id, reauthenticated_session
                )
                changed_at = self._clock()
                connection.execute(
                    "UPDATE web_users SET credential_generation = credential_generation + 1 "
                    "WHERE lifecycle != 'retired'"
                )
                connection.execute(
                    "UPDATE web_sessions SET revoked_at = COALESCE(revoked_at, ?), "
                    "reauthenticated_at = NULL",
                    (changed_at,),
                )
                self._scrub_restore_replacement_authorizations(connection)
                actor = self._row_for_user(connection, actor_user_id)
                assert actor is not None
                receipt_value = {
                    "action": action,
                    "target_user_id": None,
                    "credential_generation": int(actor["credential_generation"]),
                    "changed_at": changed_at,
                }
                self._record_idempotency(
                    connection,
                    key=key,
                    actor_user_id=actor_user_id,
                    action=action,
                    target_key="all",
                    request=request,
                    receipt=receipt_value,
                )
                self._append_audit(
                    connection,
                    action=action,
                    result="success",
                    actor_user_id=actor_user_id,
                    audit_context=audit_context,
                )
                connection.commit()
                return self._receipt_from_json(receipt_value)
            except ValidationError:
                connection.rollback()
                self._append_rejected_audit(
                    action=action,
                    actor_user_id=actor_user_id,
                    target_user_id=None,
                    result="rejected",
                    audit_context=audit_context,
                )
                raise

    def list_audit_events(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM web_auth_audit ORDER BY id"
            ).fetchall()
        return [
            {
                "created_at": float(row["created_at"]),
                "action": str(row["action"]),
                "actor_user_id": row["actor_user_id"],
                "target_user_id": row["target_user_id"],
                "user_id": row["target_user_id"],
                "login_name": row["login_name"],
                "result": str(row["result"]),
                "request_id": row["request_id"],
                "remote_address": row["remote_address"],
                "payload": json.loads(str(row["payload_json"])),
            }
            for row in rows
        ]

    def record_critical_recovery_rejection(
        self,
        *,
        actor_user_id: int,
        result: str,
        audit_context: AuditContext | None = None,
    ) -> None:
        """Persist a pre-daemon rejection for the protected recovery surface."""

        if result not in {"role_denied", "recent_reauthentication_required"}:
            raise ValidationError("Invalid critical-recovery rejection outcome")
        self._append_rejected_audit(
            action="critical_recovery.access",
            actor_user_id=actor_user_id,
            target_user_id=actor_user_id,
            result=result,
            audit_context=audit_context,
        )


class SessionManager:
    """Issue generation-bound sessions while persisting only token hashes."""

    def __init__(
        self,
        store: AuthStore,
        *,
        clock: Callable[[], float] = time.time,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        idle_lifetime_seconds: float = 1_800,
        absolute_lifetime_seconds: float = 43_200,
        reauthentication_limiter: ReauthenticationRateLimiter | None = None,
    ) -> None:
        if idle_lifetime_seconds <= 0 or absolute_lifetime_seconds <= 0:
            raise ValueError("session lifetimes must be positive")
        self.store = store
        self._clock = clock
        self._random_bytes = random_bytes
        self._idle_lifetime_seconds = idle_lifetime_seconds
        self._absolute_lifetime_seconds = absolute_lifetime_seconds
        self._reauthentication_limiter = (
            reauthentication_limiter
            if reauthentication_limiter is not None
            else ReauthenticationRateLimiter(clock=clock)
        )
        with closing(self.store._connect()) as connection:
            self.store._validate_current_schema(connection)

    def _random_token(self) -> str:
        return (
            base64.urlsafe_b64encode(self._random_bytes(_TOKEN_BYTES))
            .rstrip(b"=")
            .decode("ascii")
        )

    @staticmethod
    def _hash_token(token: str) -> str:
        return _token_hash(token)

    @staticmethod
    def _session_row(
        connection: sqlite3.Connection, token_hash: str
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT s.*, u.login_name, u.role, u.lifecycle,
                   u.credential_generation AS user_generation,
                   u.created_at AS user_created_at, u.last_login_at
            FROM web_sessions AS s
            JOIN web_users AS u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()

    @staticmethod
    def _row_user(row: sqlite3.Row) -> User:
        return User(
            id=int(row["user_id"]),
            login_name=str(row["login_name"]),
            role=str(row["role"]),
            state=str(row["lifecycle"]),
            credential_generation=int(row["user_generation"]),
            created_at=float(row["user_created_at"]),
            last_login_at=(
                None if row["last_login_at"] is None else float(row["last_login_at"])
            ),
        )

    @staticmethod
    def _row_is_active(row: sqlite3.Row, now: float) -> bool:
        return (
            row["revoked_at"] is None
            and row["lifecycle"] == "active"
            and int(row["credential_generation"]) == int(row["user_generation"])
            and now < float(row["idle_expires_at"])
            and now < float(row["absolute_expires_at"])
        )

    def _insert_session(
        self,
        connection: sqlite3.Connection,
        user: User,
        now: float,
        *,
        created_at: float | None = None,
        absolute_expires_at: float | None = None,
        reauthenticated_at: float | None = None,
    ) -> Session:
        cookie = self._random_token()
        csrf_token = self._random_token()
        session_created_at = now if created_at is None else created_at
        session_absolute_expires_at = (
            now + self._absolute_lifetime_seconds
            if absolute_expires_at is None
            else absolute_expires_at
        )
        idle_expires_at = min(
            now + self._idle_lifetime_seconds, session_absolute_expires_at
        )
        connection.execute(
            """
            INSERT INTO web_sessions (
                token_hash, user_id, credential_generation, csrf_hash,
                created_at, last_seen_at, idle_expires_at, absolute_expires_at,
                revoked_at, reauthenticated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
            """,
            (
                self._hash_token(cookie),
                user.id,
                user.credential_generation,
                self._hash_token(csrf_token),
                session_created_at,
                now,
                idle_expires_at,
                session_absolute_expires_at,
                reauthenticated_at,
            ),
        )
        return Session(
            cookie=cookie,
            csrf_token=csrf_token,
            user=user,
            created_at=session_created_at,
            idle_expires_at=idle_expires_at,
            absolute_expires_at=session_absolute_expires_at,
            reauthenticated_at=reauthenticated_at,
        )

    def create(
        self, user: User, *, audit_context: AuditContext | None = None
    ) -> Session:
        now = self._clock()
        with closing(self.store._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self.store._row_for_user(connection, user.id)
            if (
                row is None
                or row["lifecycle"] != "active"
                or int(row["credential_generation"]) != user.credential_generation
            ):
                connection.rollback()
                raise ValidationError("WebUI user unavailable")
            persisted = self.store._user_from_row(row)
            session = self._insert_session(connection, persisted, now)
            self.store._append_audit(
                connection,
                action="session.created",
                result="success",
                target_user_id=persisted.id,
                audit_context=audit_context,
            )
            connection.commit()
        return session

    def resolve(self, cookie: str) -> User | None:
        token_hash = self._hash_token(cookie)
        now = self._clock()
        resolved_user: User | None = None
        with closing(self.store._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._session_row(connection, token_hash)
            if row is None:
                connection.rollback()
                return None
            if not self._row_is_active(row, now):
                if row["revoked_at"] is None:
                    connection.execute(
                        "UPDATE web_sessions SET revoked_at = ?, reauthenticated_at = NULL "
                        "WHERE token_hash = ?",
                        (now, token_hash),
                    )
                    self.store._scrub_restore_replacement_authorizations(
                        connection, session_binding_sha256=token_hash
                    )
                    connection.commit()
                else:
                    connection.rollback()
            else:
                idle_expires_at = min(
                    now + self._idle_lifetime_seconds,
                    float(row["absolute_expires_at"]),
                )
                connection.execute(
                    "UPDATE web_sessions SET last_seen_at = ?, idle_expires_at = ? "
                    "WHERE token_hash = ?",
                    (now, idle_expires_at, token_hash),
                )
                connection.commit()
                resolved_user = self._row_user(row)
        return resolved_user

    def verify_csrf(self, cookie: str, supplied_token: str) -> bool:
        token_hash = self._hash_token(cookie)
        now = self._clock()
        with closing(self.store._connect()) as connection:
            row = self._session_row(connection, token_hash)
        if row is None or not self._row_is_active(row, now):
            return False
        return constant_time_matches(
            str(row["csrf_hash"]), self._hash_token(supplied_token)
        )

    def revoke(
        self, cookie: str, *, audit_context: AuditContext | None = None
    ) -> bool:
        token_hash = self._hash_token(cookie)
        now = self._clock()
        with closing(self.store._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._session_row(connection, token_hash)
            if row is None or not self._row_is_active(row, now):
                connection.rollback()
                return False
            cursor = connection.execute(
                "UPDATE web_sessions SET revoked_at = ?, reauthenticated_at = NULL "
                "WHERE token_hash = ?",
                (now, token_hash),
            )
            self.store._append_audit(
                connection,
                action="session.revoked",
                result="success",
                actor_user_id=int(row["user_id"]),
                target_user_id=int(row["user_id"]),
                audit_context=audit_context,
            )
            self.store._scrub_restore_replacement_authorizations(
                connection, session_binding_sha256=token_hash
            )
            connection.commit()
            revoked = cursor.rowcount == 1
        return revoked

    def rotate(
        self, cookie: str, *, audit_context: AuditContext | None = None
    ) -> Session | None:
        token_hash = self._hash_token(cookie)
        now = self._clock()
        with closing(self.store._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._session_row(connection, token_hash)
            if row is None:
                connection.rollback()
                return None
            if not self._row_is_active(row, now):
                if row["revoked_at"] is None:
                    connection.execute(
                        "UPDATE web_sessions SET revoked_at = ?, reauthenticated_at = NULL "
                        "WHERE token_hash = ?",
                        (now, token_hash),
                    )
                    self.store._scrub_restore_replacement_authorizations(
                        connection, session_binding_sha256=token_hash
                    )
                    connection.commit()
                else:
                    connection.rollback()
                return None
            connection.execute(
                "UPDATE web_sessions SET revoked_at = ?, reauthenticated_at = NULL "
                "WHERE token_hash = ?",
                (now, token_hash),
            )
            user = self._row_user(row)
            rotated = self._insert_session(
                connection,
                user,
                now,
                created_at=float(row["created_at"]),
                absolute_expires_at=float(row["absolute_expires_at"]),
                reauthenticated_at=(
                    None
                    if row["reauthenticated_at"] is None
                    else float(row["reauthenticated_at"])
                ),
            )
            self.store._append_audit(
                connection,
                action="session.rotated",
                result="success",
                actor_user_id=user.id,
                target_user_id=user.id,
                audit_context=audit_context,
            )
            self.store._scrub_restore_replacement_authorizations(
                connection, session_binding_sha256=token_hash
            )
            connection.commit()
        return rotated

    def reauthenticate(
        self,
        cookie: str,
        password: str,
        *,
        idempotency_key: str | None = None,
        audit_context: AuditContext | None = None,
    ) -> bool:
        token_hash = self._hash_token(cookie)
        key = (
            None
            if idempotency_key is None
            else self.store._validate_idempotency_key(idempotency_key)
        )
        now = self._clock()
        limiter_key = token_hash[:32]
        if not self._reauthentication_limiter.allowed(limiter_key, "session"):
            with closing(self.store._connect()) as connection:
                identity = connection.execute(
                    "SELECT user_id FROM web_sessions WHERE token_hash = ?",
                    (token_hash,),
                ).fetchone()
            user_id = None if identity is None else int(identity["user_id"])
            self.store._append_rejected_audit(
                action="account.reauthenticated",
                actor_user_id=user_id,
                target_user_id=user_id,
                result="rate_limited",
                audit_context=audit_context,
            )
            return False
        with closing(self.store._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._session_row(connection, token_hash)
            valid = row is not None and self._row_is_active(row, now)
            if valid and key is not None:
                replay = self.store._idempotent_replay(
                    connection,
                    key=key,
                    actor_user_id=int(row["user_id"]),
                    action="account.reauthenticated",
                    target_key=str(int(row["user_id"])),
                    request={"session_token_hash": token_hash},
                )
                if replay is not None:
                    attempt_hash = replay.get("credential_attempt_hash")
                    if not isinstance(attempt_hash, str):
                        connection.rollback()
                        raise ValidationError("Idempotency key conflict")
                    try:
                        _PASSWORD_HASHER.verify(attempt_hash, password)
                    except (
                        VerifyMismatchError,
                        VerificationError,
                        InvalidHashError,
                    ):
                        connection.rollback()
                        raise ValidationError("Idempotency key conflict") from None
                    connection.rollback()
                    return self.recently_reauthenticated(cookie)
            if valid:
                try:
                    user = self.store._row_for_user(connection, int(row["user_id"]))
                    assert user is not None
                    _PASSWORD_HASHER.verify(str(user["password_hash"]), password)
                except (VerifyMismatchError, VerificationError, InvalidHashError):
                    valid = False
            if not valid:
                connection.rollback()
                self._reauthentication_limiter.record_failure(
                    limiter_key, "session"
                )
                self.store._append_rejected_audit(
                    action="account.reauthenticated",
                    actor_user_id=(None if row is None else int(row["user_id"])),
                    target_user_id=(None if row is None else int(row["user_id"])),
                    result="invalid_credentials",
                    audit_context=audit_context,
                )
                return False
            user_id = int(row["user_id"])
            connection.execute(
                "UPDATE web_sessions SET reauthenticated_at = ? WHERE token_hash = ?",
                (now, token_hash),
            )
            if key is not None:
                self.store._record_idempotency(
                    connection,
                    key=key,
                    actor_user_id=user_id,
                    action="account.reauthenticated",
                    target_key=str(user_id),
                    request={"session_token_hash": token_hash},
                    receipt={
                        "credential_attempt_hash": _PASSWORD_HASHER.hash(password),
                        "user_id": user_id,
                    },
                )
            self.store._append_audit(
                connection,
                action="account.reauthenticated",
                result="success",
                actor_user_id=user_id,
                target_user_id=user_id,
                audit_context=audit_context,
            )
            connection.commit()
            self._reauthentication_limiter.record_success(limiter_key, "session")
            return True

    def recently_reauthenticated(self, cookie: str) -> bool:
        now = self._clock()
        with closing(self.store._connect()) as connection:
            row = self._session_row(connection, self._hash_token(cookie))
        if row is None or not self._row_is_active(row, now):
            return False
        reauthenticated_at = row["reauthenticated_at"]
        return reauthenticated_at is not None and now <= float(
            reauthenticated_at
        ) + _REAUTHENTICATION_SECONDS

    def reauthentication_evidence(
        self, cookie: str
    ) -> SessionReauthenticationEvidence | None:
        """Return fresh session-bound evidence while keeping the raw cookie local."""

        token_hash = self._hash_token(cookie)
        now = self._clock()
        with closing(self.store._connect()) as connection:
            row = self._session_row(connection, token_hash)
        if row is None or not self._row_is_active(row, now):
            return None
        reauthenticated_at = row["reauthenticated_at"]
        if reauthenticated_at is None or now > float(
            reauthenticated_at
        ) + _REAUTHENTICATION_SECONDS:
            return None
        return SessionReauthenticationEvidence(
            session_binding_sha256=token_hash,
            reauthenticated_at=float(reauthenticated_at),
        )

    def active_session_count(self) -> int:
        now = self._clock()
        with closing(self.store._connect()) as connection:
            row = connection.execute(
                """
                SELECT COUNT(*)
                FROM web_sessions AS s
                JOIN web_users AS u ON u.id = s.user_id
                WHERE s.revoked_at IS NULL AND u.lifecycle = 'active'
                  AND s.credential_generation = u.credential_generation
                  AND s.idle_expires_at > ? AND s.absolute_expires_at > ?
                """,
                (now, now),
            ).fetchone()
        assert row is not None
        return int(row[0])
