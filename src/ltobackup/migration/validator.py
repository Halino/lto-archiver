"""Pure, fail-closed checks for a frozen Windows automatic job."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Protocol, Self

from ..util import ltfs_tape_relative_path
from .models import AcceptanceReport

SUPPORTED_BUNDLE_SCHEMAS = frozenset(
    {
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        20,
        21,
        22,
        23,
        24,
        25,
        26,
        27,
        28,
        29,
        30,
        31,
        32,
        33,
        34,
        35,
        36,
        37,
        38,
        39,
        40,
        41,
    }
)

_REQUIRED_COLUMNS = {
    "metadata": {"key", "value"},
    "automatic_jobs": {"id", "status", "total_cassettes", "current_sequence"},
    "automatic_job_libraries": {"job_id", "library_id", "sequence"},
    "automatic_cassettes": {
        "job_id",
        "sequence",
        "physical_label",
        "tape_serial",
        "status",
        "tape_id",
        "block_id",
        "copied_files",
        "copied_bytes",
        "planned_files",
        "planned_bytes",
    },
    "automatic_cassette_items": {
        "job_id",
        "sequence",
        "item_sequence",
        "library_id",
        "relative_path",
        "size",
        "mtime_ns",
    },
    "blocks": {
        "id",
        "library_id",
        "tape_id",
        "status",
        "visible",
        "planned_files",
        "planned_bytes",
        "copied_files",
        "copied_bytes",
        "started_at",
        "completed_at",
        "tape_relative_root",
    },
    "file_versions": {
        "library_id",
        "block_id",
        "tape_id",
        "relative_path",
        "tape_relative_path",
        "size",
        "mtime_ns",
        "sha256",
        "visible",
    },
    "tapes": {"id", "cassette_number", "filesystem", "status"},
}

_SCHEMA_35_REQUIRED_COLUMNS = {
    "job_plan_items": {"relative_path", "tape_relative_path"},
    "automatic_cassette_items": {"relative_path", "tape_relative_path"},
    "job_manifest_history": {"relative_path", "tape_relative_path"},
    "job_incremental_policies": {
        "job_id", "cadence", "next_eligible_at", "last_attempt_at",
        "last_success_at", "last_outcome", "revision", "updated_at",
    },
    "job_incremental_scan_leases": {
        "job_id", "run_id", "daemon_generation", "claimed_at",
    },
    "job_layout_epochs": {
        "job_id", "epoch_number", "kind", "plan_id", "plan_digest_sha256",
        "prior_epoch_sha256", "layout_fingerprint_sha256", "canonical_json",
        "created_at",
    },
    "job_layout_targets": {
        "job_id", "epoch_number", "target_sequence", "plan_sequence",
        "physical_label", "operation", "segment_id", "canonical_json",
    },
    "job_layout_target_blocks": {
        "job_id", "epoch_number", "plan_sequence", "target_sequence",
        "segment_id", "operation_id", "block_id", "created_at",
    },
    "job_incremental_pending_extensions": {
        "job_id", "base_epoch_number", "base_layout_fingerprint", "plan_id",
        "plan_digest_sha256", "discovered_files", "discovered_bytes",
        "required_additional_labels", "created_at",
    },
    "job_incremental_scan_events": {
        "run_id", "event_sequence", "job_id", "trigger", "base_layout_epoch",
        "base_layout_fingerprint", "idempotency_key_sha256", "state",
        "daemon_generation", "recorded_at", "plan_id", "plan_digest_sha256",
        "discovered_files", "discovered_bytes", "required_additional_labels",
        "error_code",
    },
}

_SCHEMA_36_REQUIRED_COLUMNS = {
    "automatic_format_authorizations": {
        "authorization_id", "job_id", "cassette_sequence", "layout_epoch",
        "layout_fingerprint_sha256", "expected_label", "expected_operation",
        "reuse_registered", "authorized_by", "authorized_at", "request_sha256",
    },
    "automatic_sequence_state": {
        "job_id", "state", "layout_epoch", "layout_fingerprint_sha256",
        "revision", "enabled_by", "enabled_at", "updated_at",
    },
    "operation_format_authorizations": {
        "operation_id", "authorization_id", "linked_at",
    },
}

_SCHEMA_38_REQUIRED_COLUMNS = {
    "operation_sequence_continuations": {
        "operation_id", "job_id", "cassette_sequence", "layout_epoch",
        "layout_fingerprint_sha256", "continuation_idempotency_key", "linked_at",
    },
}

_SCHEMA_39_REQUIRED_COLUMNS = {
    "restore_plan_destinations": {
        "plan_id", "destination_state", "kind", "root", "anchor",
        "invalidation_reason",
    },
    "restore_plan_cassettes": {
        "plan_id", "sequence", "tape_id", "cassette_number", "physical_label",
        "volume_serial", "volume_uuid", "item_count", "total_bytes",
    },
    "restore_runs": {
        "id", "plan_id", "actor", "state", "current_cassette_sequence",
        "request_sha256", "plan_fingerprint_sha256", "total_files", "total_bytes",
        "restored_files", "skipped_files", "failed_files", "copied_bytes",
        "created_at", "started_at", "completed_at", "last_error_code",
    },
    "restore_run_cassettes": {
        "run_id", "plan_id", "sequence", "plan_cassette_sequence", "tape_id",
        "cassette_number", "physical_label", "volume_label", "volume_serial",
        "volume_uuid", "state", "item_count", "total_bytes", "restored_files",
        "skipped_files", "failed_files", "copied_bytes", "operation_id",
        "started_at", "completed_at", "last_error_code",
    },
    "restore_run_items": {
        "run_id", "plan_id", "sequence", "plan_item_sequence",
        "cassette_sequence", "file_version_id", "library_id", "relative_path",
        "tape_relative_path", "tape_id", "cassette_number", "physical_label",
        "volume_label", "block_id", "size", "sha256", "copied_at",
        "is_current", "destination_relative_path", "canonical_destination",
        "state", "bytes_copied", "observed_sha256", "error_code", "started_at",
        "completed_at",
    },
    "restore_item_conflicts": {
        "id", "run_id", "item_sequence", "conflict_sequence", "file_version_id",
        "canonical_destination", "observed_size", "observed_sha256", "state",
        "authorization_id", "recorded_at", "authorized_at", "consumed_at",
    },
    "restore_replacement_authorizations": {
        "id", "conflict_id", "run_id", "item_sequence", "file_version_id",
        "canonical_destination", "observed_size", "observed_sha256",
        "administrator", "reauthentication_proof_sha256", "request_sha256",
        "state", "authorized_at", "consumed_at", "consumed_by_operation_id",
    },
}

_SCHEMA_40_REQUIRED_COLUMNS = {
    "hardware_command_executions": {"terminal_exit_code"},
    "qualification_readback_release_receipts": {
        "operation_id",
        "owner_generation",
        "unload_command_id",
        "probe_command_id",
        "release_receipt_sha256",
        "recorded_at",
    },
}
_SCHEMA_41_REQUIRED_COLUMNS = {
    "file_versions": {"source_change_ns"},
    "application_settings": {"source_change_detection_policy"},
}


_SCHEMA_40_READBACK_RECEIPT_COLUMNS = {
    "operation_id": ("text", True),
    "owner_generation": ("integer", True),
    "unload_command_id": ("text", True),
    "probe_command_id": ("text", True),
    "release_receipt_sha256": ("text", True),
    "recorded_at": ("text", True),
}

_SCHEMA_40_READBACK_RECEIPT_FOREIGN_KEYS = (
    (
        ("operation_id",), "daemon_operations", ("id",),
        "no action", "no action", "none",
    ),
    (
        ("unload_command_id",), "hardware_command_executions", ("id",),
        "no action", "no action", "none",
    ),
    (
        ("probe_command_id",), "hardware_command_executions", ("id",),
        "no action", "no action", "none",
    ),
)

_SCHEMA_40_READBACK_RECEIPT_DIGEST_CHECK = (
    "compare",
    "=",
    ("call", "length", (("identifier", "release_receipt_sha256"),)),
    ("number", "64"),
)

_SCHEMA_36_IMMUTABLE_TRIGGERS = {
    "trg_automatic_format_authorizations_no_update": (
        "automatic_format_authorizations", "before", "update",
        "immutable_automatic_format_authorization",
    ),
    "trg_automatic_format_authorizations_no_delete": (
        "automatic_format_authorizations", "before", "delete",
        "immutable_automatic_format_authorization",
    ),
    "trg_operation_format_authorizations_no_update": (
        "operation_format_authorizations", "before", "update",
        "immutable_operation_format_authorization",
    ),
    "trg_operation_format_authorizations_no_delete": (
        "operation_format_authorizations", "before", "delete",
        "immutable_operation_format_authorization",
    ),
}

_SCHEMA_38_IMMUTABLE_TRIGGERS = {
    "trg_operation_sequence_continuations_no_update": (
        "operation_sequence_continuations", "before", "update",
        "immutable_operation_sequence_continuation",
    ),
    "trg_operation_sequence_continuations_no_delete": (
        "operation_sequence_continuations", "before", "delete",
        "immutable_operation_sequence_continuation",
    ),
}

_SCHEMA_39_IMMUTABLE_TRIGGERS = {
    "restore_plan_destinations_immutable_update": (
        "restore_plan_destinations", "before", "update",
        "restore plan destination is immutable",
    ),
    "restore_plan_destinations_immutable_delete": (
        "restore_plan_destinations", "before", "delete",
        "restore plan destination is immutable",
    ),
    "restore_runs_no_delete": (
        "restore_runs", "before", "delete", "restore run evidence is immutable",
    ),
    "restore_run_cassettes_no_delete": (
        "restore_run_cassettes", "before", "delete",
        "restore run cassette evidence is immutable",
    ),
    "restore_run_items_no_delete": (
        "restore_run_items", "before", "delete",
        "restore run item evidence is immutable",
    ),
    "restore_item_conflicts_no_delete": (
        "restore_item_conflicts", "before", "delete",
        "restore conflict evidence is immutable",
    ),
    "restore_replacement_authorizations_no_delete": (
        "restore_replacement_authorizations", "before", "delete",
        "restore replacement authorization is immutable",
    ),
}

_SCHEMA_40_IMMUTABLE_TRIGGERS = {
    "qualification_readback_release_immutable": (
        "qualification_readback_release_receipts",
        "before",
        "update",
        "qualification readback release is immutable",
    ),
    "qualification_readback_release_no_delete": (
        "qualification_readback_release_receipts",
        "before",
        "delete",
        "qualification readback release is immutable",
    ),
}

_SCHEMA_39_IDENTITY_TRIGGER_CONTRACTS = {
    "restore_runs_immutable_identity": (
        "restore_runs",
        "restore run identity is immutable",
        (
            ("id", "!="), ("plan_id", "!="), ("actor", "!="),
            ("request_sha256", "!="), ("plan_fingerprint_sha256", "!="),
            ("total_files", "!="), ("total_bytes", "!="),
            ("created_at", "!="),
        ),
    ),
    "restore_run_cassettes_immutable_identity": (
        "restore_run_cassettes",
        "restore run cassette identity is immutable",
        (
            ("run_id", "!="), ("plan_id", "!="), ("sequence", "!="),
            ("plan_cassette_sequence", "!="), ("tape_id", "!="),
            ("cassette_number", "!="), ("physical_label", "!="),
            ("volume_label", "!="), ("volume_serial", "!="),
            ("volume_uuid", "is not"), ("item_count", "!="),
            ("total_bytes", "!="),
        ),
    ),
    "restore_run_items_immutable_identity": (
        "restore_run_items",
        "restore run item identity is immutable",
        (
            ("run_id", "!="), ("plan_id", "!="), ("sequence", "!="),
            ("plan_item_sequence", "!="), ("cassette_sequence", "!="),
            ("file_version_id", "!="), ("library_id", "!="),
            ("relative_path", "!="), ("tape_relative_path", "!="),
            ("tape_id", "!="), ("cassette_number", "!="),
            ("physical_label", "!="), ("volume_label", "!="),
            ("block_id", "!="), ("size", "!="), ("sha256", "!="),
            ("copied_at", "!="), ("is_current", "!="),
            ("destination_relative_path", "!="),
            ("canonical_destination", "!="),
        ),
    ),
    "restore_item_conflicts_immutable_binding": (
        "restore_item_conflicts",
        "restore conflict binding is immutable",
        (
            ("id", "!="), ("run_id", "!="), ("item_sequence", "!="),
            ("conflict_sequence", "!="), ("file_version_id", "!="),
            ("canonical_destination", "!="), ("observed_size", "!="),
            ("observed_sha256", "!="), ("recorded_at", "!="),
        ),
    ),
    "restore_replacement_authorizations_immutable_binding": (
        "restore_replacement_authorizations",
        "restore replacement authorization binding is immutable",
        (
            ("id", "!="), ("conflict_id", "!="), ("run_id", "!="),
            ("item_sequence", "!="), ("file_version_id", "!="),
            ("canonical_destination", "!="), ("observed_size", "!="),
            ("observed_sha256", "!="), ("administrator", "!="),
            ("reauthentication_proof_sha256", "!="),
            ("request_sha256", "!="), ("authorized_at", "!="),
        ),
    ),
}

_SCHEMA_39_PARTIAL_INDEX_CONTRACTS = {
    "ux_restore_one_active_run_per_plan": (
        "restore_runs",
        ("plan_id",),
        ("planned", "waiting_media", "restoring", "paused", "recovery_required"),
    ),
    "ux_restore_item_one_open_conflict": (
        "restore_item_conflicts",
        ("run_id", "item_sequence"),
        ("recorded", "authorized"),
    ),
}

_SCHEMA_39_STATE_CONTRACTS = {
    "restore_runs": (
        "planned", "waiting_media", "restoring", "paused", "completed",
        "cancelled", "failed", "recovery_required",
    ),
    "restore_run_cassettes": (
        "pending", "waiting_media", "restoring", "completed", "failed",
        "recovery_required",
    ),
    "restore_run_items": (
        "pending", "restoring", "restored", "skipped_verified", "failed",
        "recovery_required",
    ),
    "restore_item_conflicts": ("recorded", "authorized", "consumed"),
    "restore_replacement_authorizations": ("authorized", "consumed"),
}

_AUTHORITY_CONSTRAINTS = {
    "automatic_format_authorizations": {
        "pk": ("authorization_id",),
        "foreign_keys": (
            (
                ("job_id", "cassette_sequence"),
                "automatic_cassettes",
                ("job_id", "sequence"),
                "no action", "no action", "none",
            ),
            (
                ("job_id", "layout_epoch"),
                "job_layout_epochs",
                ("job_id", "epoch_number"),
                "no action", "no action", "none",
            ),
        ),
        "checks": (
            ("compare", ">", ("identifier", "cassette_sequence"), ("number", "0")),
            ("compare", ">", ("identifier", "layout_epoch"), ("number", "0")),
            ("compare", "=", ("call", "length", (("identifier", "layout_fingerprint_sha256"),)), ("number", "64")),
            ("compare", "=", ("call", "length", (("identifier", "expected_label"),)), ("number", "6")),
            ("compare", "=", ("identifier", "expected_operation"), ("string", "format")),
            ("in", ("identifier", "reuse_registered"), (("number", "0"), ("number", "1"))),
            ("compare", "=", ("call", "length", (("identifier", "request_sha256"),)), ("number", "64")),
        ),
        "collations": {"job_id": "nocase"},
    },
    "automatic_sequence_state": {
        "pk": ("job_id",),
        "foreign_keys": (
            (
                ("job_id",), "automatic_jobs", ("id",),
                "no action", "no action", "none",
            ),
            (
                ("job_id", "layout_epoch"),
                "job_layout_epochs",
                ("job_id", "epoch_number"),
                "no action", "no action", "none",
            ),
        ),
        "checks": (
            (
                "in", ("identifier", "state"),
                (
                    ("string", "completed"), ("string", "disabled"),
                    ("string", "enabled"), ("string", "pause_pending"),
                ),
            ),
            ("compare", ">", ("identifier", "layout_epoch"), ("number", "0")),
            ("compare", "=", ("call", "length", (("identifier", "layout_fingerprint_sha256"),)), ("number", "64")),
            ("compare", ">", ("identifier", "revision"), ("number", "0")),
        ),
        "collations": {"job_id": "nocase"},
    },
    "operation_format_authorizations": {
        "pk": ("operation_id",),
        "foreign_keys": (
            (
                ("operation_id",), "format_confirmations", ("operation_id",),
                "no action", "no action", "none",
            ),
            (
                ("authorization_id",), "automatic_format_authorizations",
                ("authorization_id",), "no action", "no action", "none",
            ),
        ),
        "checks": (),
        "collations": {},
    },
}

_CONTINUATION_CONSTRAINT = {
    "pk": ("operation_id",),
    "foreign_keys": (
        (
            ("operation_id",), "daemon_operations", ("id",),
            "no action", "no action", "none",
        ),
        (
            ("job_id", "cassette_sequence"),
            "automatic_cassettes", ("job_id", "sequence"),
            "no action", "no action", "none",
        ),
        (
            ("job_id", "layout_epoch"),
            "job_layout_epochs", ("job_id", "epoch_number"),
            "no action", "no action", "none",
        ),
    ),
    "checks": (
        ("compare", ">", ("identifier", "cassette_sequence"), ("number", "0")),
        ("compare", ">", ("identifier", "layout_epoch"), ("number", "0")),
        ("compare", "=", ("call", "length", (("identifier", "layout_fingerprint_sha256"),)), ("number", "64")),
    ),
    "collations": {"job_id": "nocase"},
}

_SCHEMA_39_TABLE_CONSTRAINTS = {
    "restore_plan_destinations": {
        "pk": ("plan_id",),
        "unique": (),
        "foreign_keys": (
            (
                ("plan_id",), "restore_plans", ("id",),
                "no action", "restrict", "none",
            ),
        ),
    },
    "restore_runs": {
        "pk": ("id",),
        "unique": (("id", "plan_id"),),
        "foreign_keys": (
            (
                ("plan_id",), "restore_plans", ("id",),
                "no action", "restrict", "none",
            ),
        ),
    },
    "restore_run_cassettes": {
        "pk": ("run_id", "sequence"),
        "unique": (("run_id", "plan_cassette_sequence"),),
        "foreign_keys": (
            (
                ("operation_id",), "daemon_operations", ("id",),
                "no action", "no action", "none",
            ),
            (
                ("run_id", "plan_id"), "restore_runs", ("id", "plan_id"),
                "no action", "restrict", "none",
            ),
            (
                ("plan_id", "plan_cassette_sequence"),
                "restore_plan_cassettes", ("plan_id", "sequence"),
                "no action", "restrict", "none",
            ),
        ),
    },
    "restore_run_items": {
        "pk": ("run_id", "sequence"),
        "unique": (("run_id", "plan_item_sequence"),),
        "foreign_keys": (
            (
                ("run_id", "plan_id"), "restore_runs", ("id", "plan_id"),
                "no action", "restrict", "none",
            ),
            (
                ("run_id", "cassette_sequence"), "restore_run_cassettes",
                ("run_id", "sequence"), "no action", "restrict", "none",
            ),
            (
                ("plan_id", "plan_item_sequence"), "restore_plan_items",
                ("plan_id", "sequence"), "no action", "restrict", "none",
            ),
        ),
    },
    "restore_item_conflicts": {
        "pk": ("id",),
        "unique": (
            ("id", "run_id", "item_sequence"),
            ("run_id", "item_sequence", "conflict_sequence"),
        ),
        "foreign_keys": (
            (
                ("run_id", "item_sequence"), "restore_run_items",
                ("run_id", "sequence"), "no action", "restrict", "none",
            ),
        ),
    },
    "restore_replacement_authorizations": {
        "pk": ("id",),
        "unique": (
            ("conflict_id",),
            ("reauthentication_proof_sha256",),
        ),
        "foreign_keys": (
            (
                ("consumed_by_operation_id",), "daemon_operations", ("id",),
                "no action", "no action", "none",
            ),
            (
                ("conflict_id", "run_id", "item_sequence"),
                "restore_item_conflicts", ("id", "run_id", "item_sequence"),
                "no action", "restrict", "none",
            ),
        ),
    },
}

_PARENT_KEY_COLLATIONS = {
    "automatic_jobs": {"id": "nocase"},
    "automatic_cassettes": {"job_id": "binary"},
    "automatic_format_authorizations": {"authorization_id": "binary"},
    "format_confirmations": {"operation_id": "binary"},
    "job_layout_epochs": {"job_id": "nocase"},
}

_SCHEMA_38_PARENT_KEY_COLLATIONS = {
    "daemon_operations": {"id": "binary"},
}


def _sqlite_ddl_tokens(sql: str) -> tuple[tuple[str, str], ...]:
    """Tokenize only the SQLite declaration syntax used by protected tables."""

    tokens: list[tuple[str, str]] = []
    index = 0
    while index < len(sql):
        character = sql[index]
        if character.isspace():
            index += 1
            continue
        if sql.startswith("--", index):
            newline = sql.find("\n", index + 2)
            index = len(sql) if newline < 0 else newline + 1
            continue
        if sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            if end < 0:
                raise ValueError("unterminated SQLite DDL comment")
            index = end + 2
            continue
        if character == "'":
            value = ""
            index += 1
            while index < len(sql):
                if sql[index] == "'":
                    if index + 1 < len(sql) and sql[index + 1] == "'":
                        value += "'"
                        index += 2
                        continue
                    index += 1
                    break
                value += sql[index]
                index += 1
            else:
                raise ValueError("unterminated SQLite DDL string")
            tokens.append(("string", value))
            continue
        if character in {'"', '`', '['}:
            closing = ']' if character == '[' else character
            value = ""
            index += 1
            while index < len(sql):
                if sql[index] == closing:
                    if index + 1 < len(sql) and sql[index + 1] == closing:
                        value += closing
                        index += 2
                        continue
                    index += 1
                    break
                value += sql[index]
                index += 1
            else:
                raise ValueError("unterminated SQLite quoted identifier")
            tokens.append(("quoted_identifier", value.casefold()))
            continue
        if character.isalpha() or character in {"_", "$"}:
            end = index + 1
            while end < len(sql) and (
                sql[end].isalnum() or sql[end] in {"_", "$"}
            ):
                end += 1
            tokens.append(("identifier", sql[index:end].casefold()))
            index = end
            continue
        if character.isdigit():
            end = index + 1
            while end < len(sql) and sql[end].isdigit():
                end += 1
            tokens.append(("number", sql[index:end]))
            index = end
            continue
        operator = next(
            (
                candidate
                for candidate in ("<=", ">=", "!=", "<>", "==")
                if sql.startswith(candidate, index)
            ),
            None,
        )
        if operator is not None:
            tokens.append(("symbol", operator))
            index += len(operator)
            continue
        if character in "(),.=<>;+-*/":
            tokens.append(("symbol", character))
            index += 1
            continue
        raise ValueError(f"unsupported SQLite DDL token {character!r}")
    return tuple(tokens)


def _strip_outer_parentheses(
    tokens: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    while len(tokens) >= 2 and tokens[0] == ("symbol", "("):
        depth = 0
        matching = None
        for position, token in enumerate(tokens):
            if token == ("symbol", "("):
                depth += 1
            elif token == ("symbol", ")"):
                depth -= 1
                if depth == 0:
                    matching = position
                    break
        if matching != len(tokens) - 1:
            break
        tokens = tokens[1:-1]
    return tokens


def _identifier_value(token: tuple[str, str]) -> str:
    if token[0] not in {"identifier", "quoted_identifier"}:
        raise ValueError("SQLite identifier expected")
    return token[1]


def _is_keyword(token: tuple[str, str], keyword: str) -> bool:
    return token == ("identifier", keyword)


def _split_ddl_tokens(
    tokens: tuple[tuple[str, str], ...],
) -> tuple[tuple[tuple[str, str], ...], ...]:
    parts: list[tuple[tuple[str, str], ...]] = []
    start = 0
    depth = 0
    for position, token in enumerate(tokens):
        if token == ("symbol", "("):
            depth += 1
        elif token == ("symbol", ")"):
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced SQLite DDL")
        elif token == ("symbol", ",") and depth == 0:
            if position == start:
                raise ValueError("empty SQLite DDL item")
            parts.append(tokens[start:position])
            start = position + 1
    if depth != 0 or start >= len(tokens):
        raise ValueError("unbalanced or empty SQLite DDL")
    parts.append(tokens[start:])
    return tuple(parts)


def _check_atom(tokens: tuple[tuple[str, str], ...]):
    tokens = _strip_outer_parentheses(tokens)
    if len(tokens) == 1:
        if tokens[0][0] == "quoted_identifier":
            return ("identifier", tokens[0][1])
        if tokens[0][0] in {"identifier", "number", "string"}:
            return tokens[0]
    if (
        len(tokens) >= 4
        and tokens[0][0] in {"identifier", "quoted_identifier"}
        and tokens[1] == ("symbol", "(")
        and tokens[-1] == ("symbol", ")")
    ):
        arguments = tuple(_check_atom(part) for part in _split_ddl_tokens(tokens[2:-1]))
        return ("call", _identifier_value(tokens[0]), arguments)
    raise ValueError("unsupported SQLite CHECK atom")


def _canonical_check(tokens: tuple[tuple[str, str], ...]):
    tokens = _strip_outer_parentheses(tokens)
    depth = 0
    boundary: tuple[int, str] | None = None
    for position, token in enumerate(tokens):
        if token == ("symbol", "("):
            depth += 1
        elif token == ("symbol", ")"):
            depth -= 1
        elif depth == 0 and _is_keyword(token, "in"):
            boundary = (position, "in")
            break
        elif depth == 0 and token[0] == "symbol" and token[1] in {
            "=", "==", "<", ">", "<=", ">=", "!=", "<>",
        }:
            boundary = (position, token[1])
            break
    if boundary is None:
        raise ValueError("unsupported SQLite CHECK predicate")
    position, operator = boundary
    left = _check_atom(tokens[:position])
    if operator == "in":
        values = _strip_outer_parentheses(tokens[position + 1 :])
        if tokens[position + 1 : position + 2] != (("symbol", "("),):
            raise ValueError("unsupported SQLite CHECK IN predicate")
        members = tuple(sorted((_check_atom(part) for part in _split_ddl_tokens(values)), key=repr))
        if any(member[0] not in {"number", "string"} for member in members):
            raise ValueError("unsupported SQLite CHECK IN member")
        return ("in", left, members)
    right = _check_atom(tokens[position + 1 :])
    operator = "=" if operator == "==" else "!=" if operator == "<>" else operator
    if left[0] in {"number", "string"} and right[0] not in {"number", "string"}:
        left, right = right, left
        operator = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}.get(
            operator, operator
        )
    return ("compare", operator, left, right)


def _table_declarations(sql: str, *, parse_checks: bool = True):
    tokens = _sqlite_ddl_tokens(sql)
    opening = next(
        (position for position, token in enumerate(tokens) if token == ("symbol", "(")),
        None,
    )
    if opening is None:
        raise ValueError("SQLite CREATE TABLE body is absent")
    depth = 0
    closing = None
    for position in range(opening, len(tokens)):
        token = tokens[position]
        if token == ("symbol", "("):
            depth += 1
        elif token == ("symbol", ")"):
            depth -= 1
            if depth == 0:
                closing = position
                break
    if closing is None:
        raise ValueError("SQLite CREATE TABLE body is unbalanced")
    items = _split_ddl_tokens(tokens[opening + 1 : closing])
    collations: dict[str, str] = {}
    checks: list[tuple] = []
    table_constraints = {"primary", "unique", "foreign", "check"}
    for original_item in items:
        item = original_item
        if len(item) >= 2 and _is_keyword(item[0], "constraint"):
            if item[1][0] not in {"identifier", "quoted_identifier"}:
                raise ValueError("invalid named SQLite constraint")
            item = item[2:]
        if not item:
            raise ValueError("empty SQLite declaration")
        column_name = None
        if item[0][0] in {"identifier", "quoted_identifier"} and not (
            item[0][0] == "identifier" and item[0][1] in table_constraints
        ):
            column_name = _identifier_value(item[0])
            depth = 0
            for position, token in enumerate(item[1:], start=1):
                if token == ("symbol", "("):
                    depth += 1
                elif token == ("symbol", ")"):
                    depth -= 1
                elif depth == 0 and _is_keyword(token, "collate"):
                    if position + 1 >= len(item):
                        raise ValueError("invalid SQLite COLLATE declaration")
                    collations[column_name] = _identifier_value(item[position + 1])
        if not parse_checks:
            continue
        position = 0
        while position < len(item):
            if not _is_keyword(item[position], "check"):
                position += 1
                continue
            if position + 1 >= len(item) or item[position + 1] != ("symbol", "("):
                raise ValueError("invalid SQLite CHECK declaration")
            depth = 0
            end = None
            for candidate in range(position + 1, len(item)):
                if item[candidate] == ("symbol", "("):
                    depth += 1
                elif item[candidate] == ("symbol", ")"):
                    depth -= 1
                    if depth == 0:
                        end = candidate
                        break
            if end is None:
                raise ValueError("unbalanced SQLite CHECK declaration")
            checks.append(_canonical_check(item[position + 2 : end]))
            position = end + 1
    return collations, Counter(checks)


def _supported_table_checks(sql: str) -> Counter[tuple]:
    """Return canonical simple CHECKs while retaining closed complex predicates."""

    tokens = _sqlite_ddl_tokens(sql)
    opening = next(
        (position for position, token in enumerate(tokens) if token == ("symbol", "(")),
        None,
    )
    if opening is None:
        raise ValueError("SQLite CREATE TABLE body is absent")
    depth = 0
    closing = None
    for position in range(opening, len(tokens)):
        if tokens[position] == ("symbol", "("):
            depth += 1
        elif tokens[position] == ("symbol", ")"):
            depth -= 1
            if depth == 0:
                closing = position
                break
    if closing is None:
        raise ValueError("SQLite CREATE TABLE body is unbalanced")
    checks: Counter[tuple] = Counter()
    for item in _split_ddl_tokens(tokens[opening + 1 : closing]):
        position = 0
        while position < len(item):
            if not _is_keyword(item[position], "check"):
                position += 1
                continue
            if position + 1 >= len(item) or item[position + 1] != ("symbol", "("):
                raise ValueError("invalid SQLite CHECK declaration")
            depth = 0
            end = None
            for candidate in range(position + 1, len(item)):
                if item[candidate] == ("symbol", "("):
                    depth += 1
                elif item[candidate] == ("symbol", ")"):
                    depth -= 1
                    if depth == 0:
                        end = candidate
                        break
            if end is None:
                raise ValueError("unbalanced SQLite CHECK declaration")
            try:
                checks[_canonical_check(item[position + 2 : end])] += 1
            except ValueError:
                pass
            position = end + 1
    return checks


def _has_explicit_foreign_key_match(sql: str) -> bool:
    tokens = _sqlite_ddl_tokens(sql)
    opening = next(
        (position for position, token in enumerate(tokens) if token == ("symbol", "(")),
        None,
    )
    if opening is None:
        raise ValueError("SQLite CREATE TABLE body is absent")
    depth = 0
    closing = None
    for position in range(opening, len(tokens)):
        if tokens[position] == ("symbol", "("):
            depth += 1
        elif tokens[position] == ("symbol", ")"):
            depth -= 1
            if depth == 0:
                closing = position
                break
    if closing is None:
        raise ValueError("SQLite CREATE TABLE body is unbalanced")
    for item in _split_ddl_tokens(tokens[opening + 1 : closing]):
        references_seen = False
        for token in item:
            if _is_keyword(token, "references"):
                references_seen = True
            elif references_seen and _is_keyword(token, "match"):
                return True
    return False


def _quote_sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _trigger_matches_contract(
    sql: str,
    *,
    name: str,
    table: str,
    timing: str,
    event: str,
    marker: str,
) -> bool:
    try:
        tokens = _sqlite_ddl_tokens(sql)
        position = 0

        def keyword(value: str) -> bool:
            nonlocal position
            if position >= len(tokens) or not _is_keyword(tokens[position], value):
                return False
            position += 1
            return True

        def identifier(value: str) -> bool:
            nonlocal position
            if position >= len(tokens):
                return False
            try:
                observed = _identifier_value(tokens[position])
            except ValueError:
                return False
            if observed != value.casefold():
                return False
            position += 1
            return True

        def symbol(value: str) -> bool:
            nonlocal position
            if position >= len(tokens) or tokens[position] != ("symbol", value):
                return False
            position += 1
            return True

        if not keyword("create") or not keyword("trigger"):
            return False
        if position < len(tokens) and _is_keyword(tokens[position], "if"):
            if not keyword("if") or not keyword("not") or not keyword("exists"):
                return False
        if not identifier(name):
            return False
        if not keyword(timing) or not keyword(event) or not keyword("on"):
            return False
        if not identifier(table):
            return False
        if position < len(tokens) and _is_keyword(tokens[position], "for"):
            if not keyword("for") or not keyword("each") or not keyword("row"):
                return False
        if not keyword("begin") or not keyword("select") or not keyword("raise"):
            return False
        if not symbol("(") or not keyword("abort") or not symbol(","):
            return False
        if position >= len(tokens) or tokens[position] != ("string", marker):
            return False
        position += 1
        if not symbol(")"):
            return False
        if position < len(tokens) and tokens[position] == ("symbol", ";"):
            position += 1
        if not keyword("end"):
            return False
        if position < len(tokens) and tokens[position] == ("symbol", ";"):
            position += 1
        return position == len(tokens)
    except (TypeError, ValueError):
        return False


def _schema_39_identity_trigger_matches(
    sql: str,
    *,
    name: str,
    table: str,
    marker: str,
    comparisons: tuple[tuple[str, str], ...],
) -> bool:
    try:
        predicate = " OR ".join(
            (
                f"NEW.{column} IS NOT OLD.{column}"
                if operator == "is not"
                else f"NEW.{column}{operator}OLD.{column}"
            )
            for column, operator in comparisons
        )
        actual = _sqlite_ddl_tokens(sql)
        candidates = (
            f"CREATE TRIGGER {name} BEFORE UPDATE ON {table} WHEN {predicate} "
            f"BEGIN SELECT RAISE(ABORT,'{marker}'); END",
            f"CREATE TRIGGER IF NOT EXISTS {name} BEFORE UPDATE ON {table} "
            f"WHEN {predicate} BEGIN SELECT RAISE(ABORT,'{marker}'); END",
        )
        return any(
            actual == _sqlite_ddl_tokens(candidate) for candidate in candidates
        )
    except (TypeError, ValueError):
        return False


def _schema_39_partial_index_matches(
    sql: str,
    *,
    name: str,
    table: str,
    columns: tuple[str, ...],
    states: tuple[str, ...],
) -> bool:
    try:
        column_sql = ",".join(columns)
        state_sql = ",".join(f"'{state}'" for state in states)
        actual = _sqlite_ddl_tokens(sql)
        candidates = (
            f"CREATE UNIQUE INDEX {name} ON {table}({column_sql}) "
            f"WHERE state IN ({state_sql})",
            f"CREATE UNIQUE INDEX IF NOT EXISTS {name} ON {table}({column_sql}) "
            f"WHERE state IN ({state_sql})",
        )
        return any(
            actual == _sqlite_ddl_tokens(candidate) for candidate in candidates
        )
    except (TypeError, ValueError):
        return False


def _schema_39_restore_destination_table_matches(sql: str) -> bool:
    """Require the complete closed destination snapshot declaration."""

    expected = """
        CREATE TABLE restore_plan_destinations (
            plan_id TEXT PRIMARY KEY
                REFERENCES restore_plans(id) ON DELETE RESTRICT,
            destination_state TEXT NOT NULL
                CHECK(destination_state IN ('exact','legacy_invalid')),
            kind TEXT CHECK(kind IS NULL OR kind='local'),
            root TEXT,
            anchor TEXT,
            invalidation_reason TEXT CHECK(
                invalidation_reason IS NULL OR
                invalidation_reason='legacy_destination_snapshot_missing'
            ),
            CHECK(
                (
                    destination_state='exact' AND kind='local'
                    AND root IS NOT NULL AND anchor IS NOT NULL
                    AND invalidation_reason IS NULL
                    AND length(root) BETWEEN 1 AND 4096
                    AND length(anchor) BETWEEN 1 AND 4096
                    AND instr(root,char(0))=0
                    AND instr(anchor,char(0))=0
                    AND substr(root,1,1)='/'
                    AND substr(anchor,1,1)='/'
                    AND root NOT GLOB '*//*'
                    AND anchor NOT GLOB '*//*'
                    AND root NOT GLOB '*/./*'
                    AND anchor NOT GLOB '*/./*'
                    AND root NOT GLOB '*/.'
                    AND anchor NOT GLOB '*/.'
                    AND root NOT GLOB '*/../*'
                    AND anchor NOT GLOB '*/../*'
                    AND root NOT GLOB '*/..'
                    AND anchor NOT GLOB '*/..'
                    AND (root='/' OR root NOT GLOB '*/')
                    AND (anchor='/' OR anchor NOT GLOB '*/')
                    AND (
                        anchor='/' OR root=anchor OR (
                            substr(root,1,length(anchor))=anchor
                            AND substr(root,length(anchor)+1,1)='/'
                        )
                    )
                ) OR (
                    destination_state='legacy_invalid' AND kind IS NULL
                    AND root IS NULL AND anchor IS NULL
                    AND invalidation_reason='legacy_destination_snapshot_missing'
                )
            )
        )
    """
    try:
        return _sqlite_ddl_tokens(sql) == _sqlite_ddl_tokens(expected)
    except (TypeError, ValueError):
        return False


class CatalogView(Protocol):
    connection: sqlite3.Connection


@dataclass(frozen=True)
class CatalogContractValidation:
    """Hardware-free result of validating one live catalog schema contract."""

    schema_version: int | None
    valid: bool
    error_codes: tuple[str, ...]


class ReadOnlyCatalog:
    """SQLite read-only view that cannot initialize or modify a source catalog."""

    def __init__(self, path: Path) -> None:
        database = Path(path).resolve(strict=True)
        self.connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA query_only = ON")

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def assignment_sha256_from_rows(rows) -> str:
    """Hash the legacy ordered item-assignment contract without redefining it."""

    ordered_assignments = tuple(
        MigrationValidator._canonical_assignment(row) for row in rows
    )
    return hashlib.sha256(
        json.dumps(
            ordered_assignments,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def canonical_assignment_sha256(connection: sqlite3.Connection, job_id: str) -> str:
    """Recompute the exact legacy assignment digest from ordered item rows."""

    rows = connection.execute(
        "SELECT sequence, item_sequence, library_id, relative_path, size, mtime_ns "
        "FROM automatic_cassette_items WHERE job_id=? "
        "ORDER BY sequence, item_sequence",
        (job_id,),
    ).fetchall()
    return assignment_sha256_from_rows(rows)


def canonical_sequence_manifest_sha256(
    connection: sqlite3.Connection, job_id: str, sequence: int
) -> str:
    """Hash one exact ordered frozen cassette manifest."""

    if (
        not isinstance(job_id, str)
        or not job_id
        or type(sequence) is not int
        or sequence < 1
    ):
        raise ValueError("manifest coordinates are invalid")
    rows = connection.execute(
        "SELECT sequence, item_sequence, library_id, relative_path, size, mtime_ns "
        "FROM automatic_cassette_items WHERE job_id=? AND sequence=? "
        "ORDER BY item_sequence",
        (job_id, sequence),
    ).fetchall()
    if not rows:
        raise ValueError("cassette manifest is missing")
    return hashlib.sha256(
        b"lto-frozen-sequence-manifest-v1\0"
        + json.dumps(
            tuple(MigrationValidator._canonical_assignment(row) for row in rows),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def canonical_cassette_plan_sha256(
    connection: sqlite3.Connection,
    job_id: str,
    *,
    assignment_sha256: str | None = None,
) -> str:
    """Hash immutable cassette identity separately from the legacy item hash."""

    assignment = assignment_sha256 or canonical_assignment_sha256(connection, job_id)
    job = connection.execute(
        "SELECT id, media_key, library_id, total_cassettes, force_format "
        "FROM automatic_jobs WHERE id=?",
        (job_id,),
    ).fetchone()
    if job is None:
        raise ValueError("automatic job is missing")
    libraries = connection.execute(
        "SELECT library_id, sequence FROM automatic_job_libraries "
        "WHERE job_id=? ORDER BY sequence",
        (job_id,),
    ).fetchall()
    cassettes = connection.execute(
        "SELECT sequence, physical_label, tape_serial, planned_files, "
        "planned_bytes, operation, reuse_registered FROM automatic_cassettes "
        "WHERE job_id=? ORDER BY sequence",
        (job_id,),
    ).fetchall()
    payload = {
        "assignment_sha256": assignment,
        "job": {
            "id": job["id"] if isinstance(job["id"], str) else None,
            "media_key": (
                job["media_key"] if isinstance(job["media_key"], str) else None
            ),
            "library_id": (
                job["library_id"] if isinstance(job["library_id"], str) else None
            ),
            "total_cassettes": MigrationValidator._nonnegative_integer(
                job["total_cassettes"]
            ),
            "force_format": MigrationValidator._nonnegative_integer(
                job["force_format"]
            ),
        },
        "libraries": tuple(
            {
                "library_id": (
                    row["library_id"] if isinstance(row["library_id"], str) else None
                ),
                "sequence": MigrationValidator._nonnegative_integer(row["sequence"]),
            }
            for row in libraries
        ),
        "cassettes": tuple(
            {
                "sequence": MigrationValidator._nonnegative_integer(row["sequence"]),
                "physical_label": (
                    row["physical_label"]
                    if isinstance(row["physical_label"], str)
                    else None
                ),
                "tape_serial": (
                    row["tape_serial"] if isinstance(row["tape_serial"], str) else None
                ),
                "planned_files": MigrationValidator._nonnegative_integer(
                    row["planned_files"]
                ),
                "planned_bytes": MigrationValidator._nonnegative_integer(
                    row["planned_bytes"]
                ),
                "operation": (
                    row["operation"] if isinstance(row["operation"], str) else None
                ),
                "reuse_registered": MigrationValidator._nonnegative_integer(
                    row["reuse_registered"]
                ),
            }
            for row in cassettes
        ),
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(b"lto-frozen-cassette-plan-v1\0" + encoded).hexdigest()


def canonical_completed_evidence_sha256(
    connection: sqlite3.Connection,
    job_id: str,
    sequences: tuple[int, ...],
    *,
    allow_missing_assignments: bool,
) -> str:
    """Validate and hash exact relational commit evidence without media access."""

    if (
        not isinstance(job_id, str)
        or not job_id
        or not sequences
        or any(type(sequence) is not int or sequence < 1 for sequence in sequences)
        or sequences != tuple(sorted(set(sequences)))
    ):
        raise ValueError("completed cassette evidence coordinates are invalid")
    errors: set[str] = set()
    all_cassettes = MigrationValidator._cassettes(connection, job_id, errors)
    selected = [row for row in all_cassettes if row["sequence"] in sequences]
    libraries = MigrationValidator._job_libraries(connection, job_id, errors)
    assigned_libraries = {
        row["library_id"].casefold()
        for row in libraries
        if isinstance(row["library_id"], str)
    }
    blocks = MigrationValidator._blocks(connection, errors)
    versions = MigrationValidator._file_versions(connection, errors)
    tapes = MigrationValidator._tapes(connection, errors)
    if (
        len(selected) != len(sequences)
        or tuple(row["sequence"] for row in selected) != sequences
    ):
        errors.add("completed-evidence-sequence-invalid")
    MigrationValidator._validate_completed_cassettes(
        selected,
        blocks,
        versions,
        tapes,
        assigned_libraries,
        errors,
    )

    referenced_block_ids = tuple(
        block_id
        for cassette in selected
        for block_id in MigrationValidator._block_ids(cassette["block_id"])
    )
    referenced_set = set(referenced_block_ids)
    if len(referenced_set) != len(referenced_block_ids):
        errors.add("completed-block-reused")
    all_catalog_cassettes = list(
        connection.execute("SELECT job_id, sequence, block_id FROM automatic_cassettes")
    )
    for cassette in all_catalog_cassettes:
        if cassette["job_id"] == job_id and cassette["sequence"] in sequences:
            continue
        if referenced_set.intersection(
            MigrationValidator._block_ids(cassette["block_id"])
        ):
            errors.add("completed-block-rebound")

    assignments = list(
        connection.execute(
            "SELECT sequence, item_sequence, library_id, relative_path, size, "
            "mtime_ns FROM automatic_cassette_items WHERE job_id=? "
            "AND sequence IN (" + ",".join("?" for _ in sequences) + ") "
            "ORDER BY sequence, item_sequence",
            (job_id, *sequences),
        )
    )
    blocks_by_id = {row["id"]: row for row in blocks}
    versions_by_sequence: dict[int, list[sqlite3.Row]] = defaultdict(list)
    for cassette in selected:
        for block_id in MigrationValidator._block_ids(cassette["block_id"]):
            versions_by_sequence[cassette["sequence"]].extend(
                row for row in versions if row["block_id"] == block_id
            )
    assignments_by_sequence: dict[int, list[sqlite3.Row]] = defaultdict(list)
    for row in assignments:
        assignments_by_sequence[row["sequence"]].append(row)
    for sequence in sequences:
        cassette_assignments = assignments_by_sequence[sequence]
        if not cassette_assignments and allow_missing_assignments:
            continue
        if tuple(row["item_sequence"] for row in cassette_assignments) != tuple(
            range(1, len(cassette_assignments) + 1)
        ):
            errors.add("completed-assignment-sequence-invalid")
        assignment_values = Counter(
            (
                row["library_id"].casefold()
                if isinstance(row["library_id"], str)
                else None,
                row["relative_path"],
                row["size"],
                row["mtime_ns"],
            )
            for row in cassette_assignments
        )
        version_values = Counter(
            (
                row["library_id"].casefold()
                if isinstance(row["library_id"], str)
                else None,
                row["relative_path"],
                row["size"],
                row["mtime_ns"],
            )
            for row in versions_by_sequence[sequence]
        )
        if assignment_values != version_values:
            errors.add("completed-assignment-evidence-invalid")
    if errors:
        raise ValueError("completed cassette evidence is invalid")

    tape_rows = {
        row["id"].casefold(): row
        for row in connection.execute(
            "SELECT id, volume_serial, volume_label, cassette_number, filesystem, "
            "status FROM tapes"
        )
        if isinstance(row["id"], str)
    }
    canonical_cassettes = []
    for cassette in selected:
        block_ids = MigrationValidator._block_ids(cassette["block_id"])
        cassette_blocks = [blocks_by_id[block_id] for block_id in block_ids]
        cassette_versions = [
            row
            for block_id in block_ids
            for row in versions
            if row["block_id"] == block_id
        ]
        tape = tape_rows[cassette["tape_id"].casefold()]
        canonical_cassettes.append(
            {
                "cassette": {
                    key: cassette[key]
                    for key in (
                        "sequence",
                        "physical_label",
                        "status",
                        "tape_id",
                        "block_id",
                        "planned_files",
                        "planned_bytes",
                        "copied_files",
                        "copied_bytes",
                        "started_at",
                        "completed_at",
                        "error",
                    )
                },
                "tape": {
                    key: tape[key]
                    for key in (
                        "id",
                        "volume_serial",
                        "volume_label",
                        "cassette_number",
                        "filesystem",
                        "status",
                    )
                },
                "blocks": tuple(
                    {
                        key: block[key]
                        for key in (
                            "id",
                            "library_id",
                            "tape_id",
                            "tape_relative_root",
                            "status",
                            "visible",
                            "planned_files",
                            "planned_bytes",
                            "copied_files",
                            "copied_bytes",
                            "started_at",
                            "completed_at",
                        )
                    }
                    for block in cassette_blocks
                ),
                "file_versions": tuple(
                    {
                        key: version[key]
                        for key in (
                            "library_id",
                            "block_id",
                            "tape_id",
                            "relative_path",
                            "tape_relative_path",
                            "size",
                            "mtime_ns",
                            "sha256",
                            "visible",
                        )
                    }
                    for version in sorted(
                        cassette_versions,
                        key=lambda row: (
                            block_ids.index(row["block_id"]),
                            row["library_id"].casefold(),
                            row["relative_path"],
                        ),
                    )
                ),
                "assignments": tuple(
                    {
                        key: row[key]
                        for key in (
                            "item_sequence",
                            "library_id",
                            "relative_path",
                            "size",
                            "mtime_ns",
                        )
                    }
                    for row in assignments_by_sequence[cassette["sequence"]]
                ),
            }
        )
    encoded = json.dumps(
        {"job_id": job_id, "cassettes": tuple(canonical_cassettes)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(b"lto-completed-evidence-v1\0" + encoded).hexdigest()


def validate_catalog_contract(
    connection: sqlite3.Connection, expected_schema: int
) -> CatalogContractValidation:
    """Validate a live catalog's required schema without modifying it."""

    errors: set[str] = set()
    schema_version = MigrationValidator._schema_version(connection, errors)
    if schema_version is not None and schema_version != expected_schema:
        errors.add("schema-version-mismatch")
    MigrationValidator._validate_catalog_shape(connection, errors, expected_schema)
    MigrationValidator._validate_database(connection, errors)
    return CatalogContractValidation(
        schema_version=schema_version,
        valid=not errors,
        error_codes=tuple(sorted(errors)),
    )


class MigrationValidator:
    """Validate migration eligibility without altering the inspected catalog."""

    @classmethod
    def inspect(cls, catalog: CatalogView, job_id: str) -> AcceptanceReport:
        connection = catalog.connection
        errors: set[str] = set()
        schema_version = cls._schema_version(connection, errors)
        cls._validate_catalog_shape(connection, errors, schema_version)
        cls._validate_database(connection, errors)

        job = cls._job(connection, job_id, errors)
        job_libraries = cls._job_libraries(connection, job_id, errors)
        cassettes = cls._cassettes(connection, job_id, errors)
        assignments = cls._assignments(connection, job_id, errors)
        blocks = cls._blocks(connection, errors)
        file_versions = cls._file_versions(connection, errors)
        tapes = cls._tapes(connection, errors)

        completed_sequences = tuple(
            sequence
            for row in cassettes
            if row["status"] == "completed"
            if (sequence := cls._nonnegative_integer(row["sequence"])) is not None
        )
        total_cassettes = (
            cls._nonnegative_integer(job["total_cassettes"]) if job is not None else 0
        )
        if total_cassettes is None:
            errors.add("job-value-invalid")
            total_cassettes = 0
        cls._validate_job(job, errors)
        assigned_libraries = cls._validate_job_libraries(job_libraries, job_id, errors)
        cls._validate_cassettes(cassettes, total_cassettes, completed_sequences, errors)
        cls._validate_assignments(cassettes, assignments, assigned_libraries, errors)
        cls._validate_provisional_records(cassettes, blocks, file_versions, errors)
        cls._validate_completed_cassettes(
            cassettes,
            blocks,
            file_versions,
            tapes,
            assigned_libraries,
            errors,
        )

        if schema_version not in SUPPORTED_BUNDLE_SCHEMAS:
            errors.add("schema-unsupported")
        assignment_sha256 = assignment_sha256_from_rows(assignments)
        next_sequence = cls._next_sequence(cassettes)
        return AcceptanceReport(
            job_id=job_id,
            accepted=not errors,
            next_sequence=next_sequence,
            total_cassettes=total_cassettes,
            completed_sequences=completed_sequences,
            assignment_sha256=assignment_sha256,
            error_codes=tuple(sorted(errors)),
        )

    @staticmethod
    def _schema_version(connection: sqlite3.Connection, errors: set[str]) -> int | None:
        try:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
        except sqlite3.DatabaseError:
            errors.add("schema-invalid")
            return None
        value = row[0] if row is not None else None
        if not isinstance(value, str) or not value.isdecimal():
            errors.add("schema-invalid")
            return None
        return int(value)

    @staticmethod
    def _validate_catalog_shape(
        connection: sqlite3.Connection,
        errors: set[str],
        schema_version: int | None,
    ) -> None:
        try:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        except sqlite3.DatabaseError:
            errors.add("catalog-unreadable")
            return
        required_columns = dict(_REQUIRED_COLUMNS)
        if schema_version is not None and schema_version >= 35:
            required_columns.update(_SCHEMA_35_REQUIRED_COLUMNS)
        if schema_version is not None and schema_version >= 36:
            required_columns.update(_SCHEMA_36_REQUIRED_COLUMNS)
        if schema_version is not None and schema_version >= 38:
            required_columns.update(_SCHEMA_38_REQUIRED_COLUMNS)
        if schema_version is not None and schema_version >= 39:
            required_columns.update(_SCHEMA_39_REQUIRED_COLUMNS)
        if schema_version is not None and schema_version >= 40:
            required_columns.update(_SCHEMA_40_REQUIRED_COLUMNS)
        if schema_version is not None and schema_version >= 41:
            required_columns.update(_SCHEMA_41_REQUIRED_COLUMNS)
        for table, required in required_columns.items():
            if table not in tables:
                errors.add("required-table-missing")
                continue
            columns = {
                row[1] for row in connection.execute(f"PRAGMA table_info({table})")
            }
            if not required.issubset(columns):
                errors.add("required-column-missing")
        if schema_version is not None and schema_version >= 36:
            MigrationValidator._validate_authority_constraints(
                connection, errors, schema_version
            )
            trigger_rows = {
                str(row[0]).casefold(): (str(row[1]).casefold(), str(row[2] or ""))
                for row in connection.execute(
                    "SELECT name,tbl_name,sql FROM sqlite_master WHERE type='trigger'"
                )
            }
            required_triggers = dict(_SCHEMA_36_IMMUTABLE_TRIGGERS)
            if schema_version >= 38:
                required_triggers.update(_SCHEMA_38_IMMUTABLE_TRIGGERS)
            if schema_version >= 39:
                required_triggers.update(_SCHEMA_39_IMMUTABLE_TRIGGERS)
            if schema_version >= 40:
                required_triggers.update(_SCHEMA_40_IMMUTABLE_TRIGGERS)
            for name, contract in required_triggers.items():
                trigger = trigger_rows.get(name.casefold())
                if trigger is None:
                    errors.add("required-trigger-missing")
                    continue
                table, timing, event, marker = contract
                observed_table, sql = trigger
                if observed_table != table.casefold() or not _trigger_matches_contract(
                    sql,
                    name=name,
                    table=table,
                    timing=timing,
                    event=event,
                    marker=marker,
                ):
                    errors.add("required-trigger-invalid")
            if schema_version >= 39:
                for name, contract in _SCHEMA_39_IDENTITY_TRIGGER_CONTRACTS.items():
                    trigger = trigger_rows.get(name.casefold())
                    if trigger is None:
                        errors.add("required-trigger-missing")
                        continue
                    table, marker, comparisons = contract
                    observed_table, sql = trigger
                    if (
                        observed_table != table.casefold()
                        or not _schema_39_identity_trigger_matches(
                            sql,
                            name=name,
                            table=table,
                            marker=marker,
                            comparisons=comparisons,
                        )
                    ):
                        errors.add("required-trigger-invalid")
                MigrationValidator._validate_schema_39_restore_contracts(
                    connection, errors
                )
            if schema_version >= 40:
                MigrationValidator._validate_schema_40_command_contracts(
                    connection, errors
                )
            if schema_version >= 41:
                MigrationValidator._validate_schema_41_change_contracts(
                    connection, errors
                )

    @staticmethod
    def _validate_schema_41_change_contracts(
        connection: sqlite3.Connection,
        errors: set[str],
    ) -> None:
        expected = {
            "file_versions": (
                "compare", ">", ("identifier", "source_change_ns"), ("number", "0")
            ),
            "application_settings": (
                "in",
                ("identifier", "source_change_detection_policy"),
                (("string", "size_mtime"), ("string", "size_mtime_change")),
            ),
        }
        for table, check in expected.items():
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if row is None:
                continue
            try:
                actual = _supported_table_checks(str(row[0]))
            except (TypeError, ValueError):
                errors.add("required-check-constraint-invalid")
                continue
            if actual[check] != 1:
                errors.add("required-check-constraint-invalid")

    @staticmethod
    def _validate_schema_40_command_contracts(
        connection: sqlite3.Connection,
        errors: set[str],
    ) -> None:
        command_columns = {
            str(row[1]).casefold(): (str(row[2]).casefold(), bool(row[3]))
            for row in connection.execute(
                "PRAGMA table_info(hardware_command_executions)"
            )
        }
        terminal_contract = command_columns.get("terminal_exit_code")
        if terminal_contract != ("integer", False):
            errors.add("required-column-contract-invalid")
        if terminal_contract is not None:
            invalid_exit = connection.execute(
                "SELECT 1 FROM hardware_command_executions "
                "WHERE terminal_exit_code IS NOT NULL AND ("
                "typeof(terminal_exit_code)!='integer' OR state!='quiesced' "
                "OR exit_outcome!='completed') LIMIT 1"
            ).fetchone()
            if invalid_exit is not None:
                errors.add("terminal-exit-code-lifecycle-invalid")

        table = "qualification_readback_release_receipts"
        table_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        if table_row is None:
            return
        quoted_table = _quote_sqlite_identifier(table)
        table_info = tuple(
            connection.execute(f"PRAGMA table_info({quoted_table})")
        )
        actual_columns = {
            str(row[1]).casefold(): (str(row[2]).casefold(), bool(row[3]))
            for row in table_info
        }
        if actual_columns != _SCHEMA_40_READBACK_RECEIPT_COLUMNS:
            errors.add("required-column-contract-invalid")
        primary_key = tuple(
            str(row[1]).casefold()
            for row in sorted(
                (row for row in table_info if int(row[5]) > 0),
                key=lambda row: int(row[5]),
            )
        )
        if primary_key != ("operation_id",):
            errors.add("required-primary-key-invalid")

        grouped_foreign_keys: dict[int, list[sqlite3.Row]] = defaultdict(list)
        for row in connection.execute(
            f"PRAGMA foreign_key_list({quoted_table})"
        ):
            grouped_foreign_keys[int(row[0])].append(row)
        foreign_keys: Counter[tuple] = Counter()
        for rows in grouped_foreign_keys.values():
            ordered = sorted(rows, key=lambda row: int(row[1]))
            foreign_keys[
                (
                    tuple(str(row[3]).casefold() for row in ordered),
                    str(ordered[0][2]).casefold(),
                    tuple(str(row[4]).casefold() for row in ordered),
                    str(ordered[0][5]).casefold(),
                    str(ordered[0][6]).casefold(),
                    str(ordered[0][7]).casefold(),
                )
            ] += 1
        if foreign_keys != Counter(_SCHEMA_40_READBACK_RECEIPT_FOREIGN_KEYS):
            errors.add("required-foreign-key-invalid")

        try:
            checks = _supported_table_checks(str(table_row[0]))
        except (TypeError, ValueError):
            errors.add("required-check-constraint-invalid")
        else:
            if checks[_SCHEMA_40_READBACK_RECEIPT_DIGEST_CHECK] != 1:
                errors.add("required-check-constraint-invalid")

    @staticmethod
    def _validate_schema_39_restore_contracts(
        connection: sqlite3.Connection,
        errors: set[str],
    ) -> None:
        destination_table = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='restore_plan_destinations'"
        ).fetchone()
        if (
            destination_table is not None
            and not _schema_39_restore_destination_table_matches(
                str(destination_table[0])
            )
        ):
            errors.add("required-check-constraint-invalid")
        for table, contract in _SCHEMA_39_TABLE_CONSTRAINTS.items():
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if row is None:
                continue
            quoted_table = _quote_sqlite_identifier(table)
            table_info = tuple(
                connection.execute(f"PRAGMA table_info({quoted_table})")
            )
            primary_key = tuple(
                str(column[1]).casefold()
                for column in sorted(
                    (column for column in table_info if int(column[5]) > 0),
                    key=lambda column: int(column[5]),
                )
            )
            if primary_key != contract["pk"]:
                errors.add("required-primary-key-invalid")

            unique_keys: Counter[tuple[str, ...]] = Counter()
            for index in connection.execute(f"PRAGMA index_list({quoted_table})"):
                if not int(index[2]) or int(index[4]):
                    continue
                if str(index[3]).casefold() == "pk":
                    continue
                quoted_index = _quote_sqlite_identifier(str(index[1]))
                columns = tuple(
                    str(column[2]).casefold()
                    for column in connection.execute(
                        f"PRAGMA index_info({quoted_index})"
                    )
                )
                unique_keys[columns] += 1
            if unique_keys != Counter(contract["unique"]):
                errors.add("required-unique-constraint-invalid")

            grouped_foreign_keys: dict[int, list[sqlite3.Row]] = defaultdict(list)
            for foreign_key in connection.execute(
                f"PRAGMA foreign_key_list({quoted_table})"
            ):
                grouped_foreign_keys[int(foreign_key[0])].append(foreign_key)
            foreign_keys: Counter[tuple] = Counter()
            for group in grouped_foreign_keys.values():
                ordered = sorted(group, key=lambda foreign_key: int(foreign_key[1]))
                foreign_keys[
                    (
                        tuple(str(key[3]).casefold() for key in ordered),
                        str(ordered[0][2]).casefold(),
                        tuple(str(key[4]).casefold() for key in ordered),
                        str(ordered[0][5]).casefold(),
                        str(ordered[0][6]).casefold(),
                        str(ordered[0][7]).casefold(),
                    )
                ] += 1
            if foreign_keys != Counter(contract["foreign_keys"]):
                errors.add("required-foreign-key-invalid")

            state_column = "destination_state" if table == (
                "restore_plan_destinations"
            ) else "state"
            state_values = (
                ("exact", "legacy_invalid")
                if table == "restore_plan_destinations"
                else _SCHEMA_39_STATE_CONTRACTS[table]
            )
            expected_state = (
                "in",
                ("identifier", state_column),
                tuple(
                    sorted(
                        (("string", state) for state in state_values), key=repr
                    )
                ),
            )
            try:
                table_checks = _supported_table_checks(str(row[0]))
            except (TypeError, ValueError):
                errors.add("required-check-constraint-invalid")
            else:
                if table_checks[expected_state] != 1:
                    errors.add("required-check-constraint-invalid")

        for name, (table, columns, states) in (
            _SCHEMA_39_PARTIAL_INDEX_CONTRACTS.items()
        ):
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name=?",
                (name,),
            ).fetchone()
            metadata = next(
                (
                    index
                    for index in connection.execute(
                        f"PRAGMA index_list({_quote_sqlite_identifier(table)})"
                    )
                    if str(index[1]).casefold() == name.casefold()
                ),
                None,
            )
            if row is None or metadata is None:
                errors.add("required-index-missing")
                continue
            if (
                int(metadata[2]) != 1
                or int(metadata[4]) != 1
                or not _schema_39_partial_index_matches(
                    str(row[0]),
                    name=name,
                    table=table,
                    columns=columns,
                    states=states,
                )
            ):
                errors.add("required-index-invalid")

    @staticmethod
    def _validate_authority_constraints(
        connection: sqlite3.Connection,
        errors: set[str],
        schema_version: int,
    ) -> None:
        contracts = dict(_AUTHORITY_CONSTRAINTS)
        if schema_version >= 38:
            contracts["operation_sequence_continuations"] = _CONTINUATION_CONSTRAINT

        for table, contract in contracts.items():
            table_sql_row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if table_sql_row is None:
                continue
            quoted_table = _quote_sqlite_identifier(table)
            table_info = tuple(
                connection.execute(f"PRAGMA table_info({quoted_table})")
            )
            primary_key = tuple(
                str(row[1]).casefold()
                for row in sorted(
                    (row for row in table_info if int(row[5]) > 0),
                    key=lambda row: int(row[5]),
                )
            )
            if primary_key != contract["pk"]:
                errors.add("required-primary-key-invalid")

            unique_keys: Counter[tuple[str, ...]] = Counter()
            for index in connection.execute(f"PRAGMA index_list({quoted_table})"):
                if not int(index[2]) or int(index[4]):
                    continue
                if str(index[3]).casefold() == "pk":
                    continue
                quoted_index = _quote_sqlite_identifier(str(index[1]))
                columns = tuple(
                    str(row[2]).casefold()
                    for row in connection.execute(f"PRAGMA index_info({quoted_index})")
                )
                unique_keys[columns] += 1
            expected_unique: Counter[tuple[str, ...]] = Counter()
            if table == "automatic_format_authorizations":
                expected_unique[
                    (
                        "job_id", "cassette_sequence", "expected_label",
                    )
                    if schema_version == 36
                    else (
                        "job_id", "cassette_sequence", "expected_label", "layout_epoch",
                    )
                ] += 1
                legacy = ("job_id", "cassette_sequence", "expected_label")
                if schema_version >= 37 and unique_keys[legacy]:
                    errors.add("legacy-authority-unique-present")
            elif table == "operation_sequence_continuations":
                expected_unique[("continuation_idempotency_key",)] += 1
            if unique_keys != expected_unique:
                errors.add("required-unique-constraint-invalid")

            grouped_foreign_keys: dict[int, list[sqlite3.Row]] = defaultdict(list)
            for row in connection.execute(f"PRAGMA foreign_key_list({quoted_table})"):
                grouped_foreign_keys[int(row[0])].append(row)
            actual_foreign_keys: Counter[tuple] = Counter()
            for rows in grouped_foreign_keys.values():
                ordered = sorted(rows, key=lambda row: int(row[1]))
                actual_foreign_keys[
                    (
                        tuple(str(row[3]).casefold() for row in ordered),
                        str(ordered[0][2]).casefold(),
                        tuple(str(row[4]).casefold() for row in ordered),
                        str(ordered[0][5]).casefold(),
                        str(ordered[0][6]).casefold(),
                        str(ordered[0][7]).casefold(),
                    )
                ] += 1
            try:
                explicit_match = _has_explicit_foreign_key_match(
                    str(table_sql_row[0])
                )
            except (TypeError, ValueError):
                explicit_match = True
            if (
                actual_foreign_keys != Counter(contract["foreign_keys"])
                or explicit_match
            ):
                errors.add("required-foreign-key-invalid")

            try:
                collations, actual_checks = _table_declarations(
                    str(table_sql_row[0])
                )
            except (TypeError, ValueError):
                errors.add("required-check-constraint-invalid")
                try:
                    collations, _ = _table_declarations(
                        str(table_sql_row[0]), parse_checks=False
                    )
                except (TypeError, ValueError):
                    errors.add("required-collation-invalid")
                    continue
            else:
                expected_checks = Counter(contract["checks"])
                if any(
                    actual_checks[predicate] < count
                    for predicate, count in expected_checks.items()
                ):
                    errors.add("required-check-constraint-invalid")
            if any(
                collations.get(column, "binary") != expected
                for column, expected in contract["collations"].items()
            ):
                errors.add("required-collation-invalid")

        parent_key_collations = dict(_PARENT_KEY_COLLATIONS)
        if schema_version >= 38:
            parent_key_collations.update(_SCHEMA_38_PARENT_KEY_COLLATIONS)
        for table, expected_collations in parent_key_collations.items():
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if row is None:
                continue
            try:
                collations, _ = _table_declarations(
                    str(row[0]), parse_checks=False
                )
            except (TypeError, ValueError):
                errors.add("required-collation-invalid")
                continue
            if any(
                collations.get(column, "binary") != expected
                for column, expected in expected_collations.items()
            ):
                errors.add("required-collation-invalid")

    @staticmethod
    def _validate_database(connection: sqlite3.Connection, errors: set[str]) -> None:
        try:
            integrity = [row[0] for row in connection.execute("PRAGMA integrity_check")]
            if integrity != ["ok"]:
                errors.add("catalog-integrity-failed")
            if list(connection.execute("PRAGMA foreign_key_check")):
                errors.add("catalog-foreign-key-failed")
        except sqlite3.DatabaseError:
            errors.add("catalog-unreadable")

    @staticmethod
    def _job(connection: sqlite3.Connection, job_id: str, errors: set[str]):
        try:
            row = connection.execute(
                "SELECT id, status, total_cassettes, current_sequence "
                "FROM automatic_jobs WHERE id=?",
                (job_id,),
            ).fetchone()
        except sqlite3.DatabaseError:
            errors.add("catalog-unreadable")
            return None
        if row is None:
            errors.add("job-not-found")
        return row

    @staticmethod
    def _cassettes(connection: sqlite3.Connection, job_id: str, errors: set[str]):
        try:
            return list(
                connection.execute(
                    "SELECT sequence, physical_label, tape_serial, status, tape_id, block_id, "
                    "copied_files, copied_bytes, "
                    "planned_files, planned_bytes, started_at, completed_at, error "
                    "FROM automatic_cassettes WHERE job_id=? ORDER BY sequence",
                    (job_id,),
                )
            )
        except sqlite3.DatabaseError:
            errors.add("catalog-unreadable")
            return []

    @staticmethod
    def _job_libraries(connection: sqlite3.Connection, job_id: str, errors: set[str]):
        try:
            return list(
                connection.execute(
                    "SELECT job_id, library_id, sequence FROM automatic_job_libraries "
                    "WHERE job_id=? ORDER BY sequence",
                    (job_id,),
                )
            )
        except sqlite3.DatabaseError:
            errors.add("catalog-unreadable")
            return []

    @staticmethod
    def _assignments(connection: sqlite3.Connection, job_id: str, errors: set[str]):
        try:
            return list(
                connection.execute(
                    "SELECT item.sequence, item.item_sequence, item.library_id, item.relative_path, "
                    "item.size, item.mtime_ns FROM automatic_cassette_items item "
                    "JOIN automatic_cassettes cassette "
                    "ON cassette.job_id=item.job_id AND cassette.sequence=item.sequence "
                    "WHERE item.job_id=? "
                    "ORDER BY item.sequence, item.item_sequence",
                    (job_id,),
                )
            )
        except sqlite3.DatabaseError:
            errors.add("catalog-unreadable")
            return []

    @staticmethod
    def _blocks(connection: sqlite3.Connection, errors: set[str]):
        try:
            return list(
                connection.execute(
                    "SELECT id, library_id, tape_id, tape_relative_root, status, visible, "
                    "planned_files, planned_bytes, copied_files, copied_bytes, started_at, "
                    "completed_at FROM blocks"
                )
            )
        except sqlite3.DatabaseError:
            errors.add("catalog-unreadable")
            return []

    @staticmethod
    def _file_versions(connection: sqlite3.Connection, errors: set[str]):
        try:
            return list(
                connection.execute(
                    "SELECT library_id, block_id, tape_id, relative_path, tape_relative_path, "
                    "size, mtime_ns, sha256, visible FROM file_versions"
                )
            )
        except sqlite3.DatabaseError:
            errors.add("catalog-unreadable")
            return []

    @staticmethod
    def _tapes(connection: sqlite3.Connection, errors: set[str]):
        try:
            return list(
                connection.execute(
                    "SELECT id, cassette_number, filesystem, status FROM tapes"
                )
            )
        except sqlite3.DatabaseError:
            errors.add("catalog-unreadable")
            return []

    @staticmethod
    def _validate_job(job, errors: set[str]) -> None:
        if job is None:
            return
        if job["status"] not in {"paused", "waiting_media"}:
            errors.add("job-not-waiting")
        if MigrationValidator._nonnegative_integer(job["current_sequence"]) != 4:
            errors.add("current-sequence-invalid")

    @staticmethod
    def _validate_job_libraries(
        job_libraries, job_id: str, errors: set[str]
    ) -> set[str]:
        assigned: set[str] = set()
        sequences: list[int] = []
        invalid = not job_libraries
        for row in job_libraries:
            library_id = row["library_id"]
            sequence = MigrationValidator._positive_integer(row["sequence"])
            if (
                row["job_id"] != job_id
                or not isinstance(library_id, str)
                or not library_id
                or sequence is None
                or library_id.casefold() in assigned
                or sequence in sequences
            ):
                invalid = True
                continue
            assigned.add(library_id.casefold())
            sequences.append(sequence)
        if tuple(sequences) != tuple(range(1, len(sequences) + 1)):
            invalid = True
        if invalid:
            errors.add("job-library-assignment-invalid")
        return assigned

    @staticmethod
    def _validate_cassettes(
        cassettes, total: int, completed: tuple[int, ...], errors: set[str]
    ) -> None:
        sequences: list[int] = []
        physical_labels: set[str] = set()
        tape_serials: set[str] = set()
        for row in cassettes:
            sequence = MigrationValidator._nonnegative_integer(row["sequence"])
            planned_files = MigrationValidator._nonnegative_integer(
                row["planned_files"]
            )
            planned_bytes = MigrationValidator._nonnegative_integer(
                row["planned_bytes"]
            )
            copied_files = MigrationValidator._nonnegative_integer(row["copied_files"])
            copied_bytes = MigrationValidator._nonnegative_integer(row["copied_bytes"])
            physical_label = row["physical_label"]
            tape_serial = row["tape_serial"]
            if None in {
                sequence,
                planned_files,
                planned_bytes,
                copied_files,
                copied_bytes,
            }:
                errors.add("cassette-value-invalid")
                continue
            sequences.append(sequence)
            if (
                not isinstance(physical_label, str)
                or not physical_label
                or not isinstance(tape_serial, str)
                or not tape_serial
                or physical_label.casefold() in physical_labels
                or tape_serial.casefold() in tape_serials
            ):
                errors.add("cassette-identity-invalid")
            else:
                physical_labels.add(physical_label.casefold())
                tape_serials.add(tape_serial.casefold())
        if total != 20 or len(cassettes) != 20:
            errors.add("cassette-count-invalid")
        if total != len(cassettes):
            errors.add("cassette-count-mismatch")
        if tuple(sequences) != tuple(range(1, 21)):
            errors.add("cassette-sequence-gap")
        if completed != (1, 2, 3):
            errors.add("completed-cassettes-invalid")
        fourth = next(
            (
                row
                for row in cassettes
                if MigrationValidator._nonnegative_integer(row["sequence"]) == 4
            ),
            None,
        )
        if fourth is None or any(
            (
                fourth["status"] not in {"pending", "waiting_media"},
                fourth["tape_id"] is not None,
                fourth["block_id"] is not None,
                MigrationValidator._nonnegative_integer(fourth["copied_files"]) != 0,
                MigrationValidator._nonnegative_integer(fourth["copied_bytes"]) != 0,
                (
                    fourth["started_at"] is not None
                    if fourth["status"] == "pending"
                    else fourth["started_at"] is not None
                    and MigrationValidator._timestamp(fourth["started_at"]) is None
                ),
                fourth["completed_at"] is not None,
                fourth["error"] is not None,
            )
        ):
            errors.add("cassette-4-not-untouched")
        for row in cassettes:
            sequence = MigrationValidator._nonnegative_integer(row["sequence"])
            if sequence is None:
                continue
            if sequence > 3 and row["block_id"] is not None:
                errors.add("provisional-block")
            if sequence > 3 and row["status"] not in {"pending", "waiting_media"}:
                errors.add("provisional-cassette")
            if sequence >= 5 and not MigrationValidator._is_pristine_cassette(row):
                errors.add("cassette-not-pristine")

    @staticmethod
    def _validate_assignments(
        cassettes, assignments, assigned_libraries: set[str], errors: set[str]
    ) -> dict[int, list[sqlite3.Row]]:
        by_sequence: dict[int, list[sqlite3.Row]] = defaultdict(list)
        seen: set[tuple[str, str]] = set()
        for row in assignments:
            sequence = MigrationValidator._nonnegative_integer(row["sequence"])
            item_sequence = MigrationValidator._nonnegative_integer(
                row["item_sequence"]
            )
            size = MigrationValidator._nonnegative_integer(row["size"])
            mtime_ns = MigrationValidator._nonnegative_integer(row["mtime_ns"])
            library_id = row["library_id"]
            path = row["relative_path"]
            if (
                sequence is None
                or item_sequence is None
                or size is None
                or mtime_ns is None
                or not isinstance(library_id, str)
                or not isinstance(path, str)
            ):
                errors.add("manifest-value-invalid")
                continue
            by_sequence[sequence].append(row)
            if not MigrationValidator._is_safe_relative_path(path):
                errors.add("manifest-path-invalid")
            if library_id.casefold() not in assigned_libraries:
                errors.add("job-library-assignment-invalid")
            key = (library_id.casefold(), path.casefold())
            if key in seen:
                errors.add("assignment-duplicate")
            seen.add(key)
        for cassette in cassettes:
            if cassette["status"] == "completed":
                continue
            sequence = MigrationValidator._nonnegative_integer(cassette["sequence"])
            planned_files = MigrationValidator._nonnegative_integer(
                cassette["planned_files"]
            )
            planned_bytes = MigrationValidator._nonnegative_integer(
                cassette["planned_bytes"]
            )
            if sequence is None or planned_files is None or planned_bytes is None:
                errors.add("cassette-value-invalid")
                continue
            items = by_sequence.get(sequence, [])
            if not items:
                if planned_files != 0 or planned_bytes != 0:
                    errors.add("manifest-missing")
                continue
            if len(items) != planned_files:
                errors.add("manifest-count-mismatch")
            if tuple(
                MigrationValidator._nonnegative_integer(row["item_sequence"])
                for row in items
            ) != tuple(range(1, planned_files + 1)):
                errors.add("manifest-sequence-invalid")
            if sum(row["size"] for row in items) != planned_bytes:
                errors.add("manifest-bytes-mismatch")
        return by_sequence

    @staticmethod
    def _validate_provisional_records(
        cassettes, blocks, file_versions, errors: set[str]
    ) -> None:
        blocks_by_id = {row["id"]: row for row in blocks}
        target_block_ids = {
            block_id
            for row in cassettes
            for block_id in MigrationValidator._block_ids(row["block_id"])
        }
        if any(
            blocks_by_id.get(block_id) is not None
            and blocks_by_id[block_id]["status"] != "completed"
            for block_id in target_block_ids
        ):
            errors.add("provisional-block-record")
        if any(
            row["block_id"] in target_block_ids
            and (
                blocks_by_id.get(row["block_id"]) is None
                or blocks_by_id[row["block_id"]]["status"] != "completed"
            )
            for row in file_versions
        ):
            errors.add("provisional-file-version-record")

    @staticmethod
    def _validate_completed_cassettes(
        cassettes,
        blocks,
        file_versions,
        tapes,
        assigned_libraries: set[str],
        errors: set[str],
    ) -> None:
        blocks_by_id = {row["id"]: row for row in blocks}
        tapes_by_id = {
            row["id"].casefold(): row for row in tapes if isinstance(row["id"], str)
        }
        files_by_block: dict[str, list[sqlite3.Row]] = defaultdict(list)
        for row in file_versions:
            files_by_block[row["block_id"]].append(row)
        seen_block_ids: set[str] = set()
        seen_tape_ids: set[str] = set()
        for cassette in cassettes:
            if cassette["status"] != "completed":
                continue
            block_ids = MigrationValidator._block_ids(cassette["block_id"])
            duplicate_blocks = seen_block_ids.intersection(block_ids)
            if duplicate_blocks:
                errors.add("completed-block-reused")
            seen_block_ids.update(block_ids)
            tape_id = cassette["tape_id"]
            tape_key = tape_id.casefold() if isinstance(tape_id, str) else None
            if tape_key is not None and tape_key in seen_tape_ids:
                errors.add("completed-tape-reused")
            if tape_key is not None:
                seen_tape_ids.add(tape_key)
            cassette_blocks = [blocks_by_id.get(block_id) for block_id in block_ids]
            planned_files = MigrationValidator._nonnegative_integer(
                cassette["planned_files"]
            )
            planned_bytes = MigrationValidator._nonnegative_integer(
                cassette["planned_bytes"]
            )
            copied_files = MigrationValidator._nonnegative_integer(
                cassette["copied_files"]
            )
            copied_bytes = MigrationValidator._nonnegative_integer(
                cassette["copied_bytes"]
            )
            versions = [
                version
                for block_id in block_ids
                for version in files_by_block.get(block_id, [])
            ]
            if any(
                block is not None
                and (
                    not isinstance(block["library_id"], str)
                    or block["library_id"].casefold() not in assigned_libraries
                )
                for block in cassette_blocks
            ) or any(
                not isinstance(version["library_id"], str)
                or version["library_id"].casefold() not in assigned_libraries
                for version in versions
            ):
                errors.add("job-library-assignment-invalid")
            tape = tapes_by_id.get(tape_key) if tape_key is not None else None
            if not MigrationValidator._completed_media_matches(cassette, tape):
                errors.add("completed-media-identity-invalid")
            if not MigrationValidator._completed_blocks_match(
                cassette,
                cassette_blocks,
                block_ids,
                files_by_block,
                assigned_libraries,
                planned_files,
                planned_bytes,
                copied_files,
                copied_bytes,
            ):
                errors.add("completed-cassette-block-invalid")
            if not MigrationValidator._completed_timestamps_valid(
                cassette, cassette_blocks
            ):
                errors.add("completed-cassette-timestamp-invalid")
            if not MigrationValidator._completed_totals_match(
                versions,
                cassette_blocks,
                cassette,
                planned_files,
                planned_bytes,
                copied_files,
                copied_bytes,
            ):
                errors.add("completed-cassette-total-invalid")
            if not MigrationValidator._completed_manifest_matches(
                blocks_by_id, block_ids, versions, planned_files, planned_bytes
            ):
                errors.add("completed-cassette-manifest-invalid")

    @staticmethod
    def _completed_blocks_match(
        cassette,
        blocks,
        block_ids,
        files_by_block,
        assigned_libraries,
        planned_files,
        planned_bytes,
        copied_files,
        copied_bytes,
    ) -> bool:
        if (
            not block_ids
            or len(block_ids) != len(set(block_ids))
            or any(block is None for block in blocks)
            or cassette["status"] != "completed"
            or not isinstance(cassette["tape_id"], str)
            or None in {planned_files, planned_bytes, copied_files, copied_bytes}
        ):
            return False
        block_values = []
        for block in blocks:
            values = tuple(
                MigrationValidator._nonnegative_integer(block[column])
                for column in (
                    "planned_files",
                    "planned_bytes",
                    "copied_files",
                    "copied_bytes",
                )
            )
            if (
                not MigrationValidator._same_catalog_identifier(
                    block["tape_id"], cassette["tape_id"]
                )
                or not isinstance(block["library_id"], str)
                or block["library_id"].casefold() not in assigned_libraries
                or block["status"] != "completed"
                or block["visible"] != 1
                or any(value is None for value in values)
                or any(
                    not isinstance(version["library_id"], str)
                    or version["library_id"].casefold()
                    != block["library_id"].casefold()
                    or version["library_id"].casefold() not in assigned_libraries
                    for version in files_by_block.get(block["id"], [])
                )
            ):
                return False
            block_values.append(values)
        return tuple(
            sum(values[index] for values in block_values) for index in range(4)
        ) == (
            planned_files,
            planned_bytes,
            copied_files,
            copied_bytes,
        )

    @staticmethod
    def _completed_media_matches(cassette, tape) -> bool:
        if tape is None:
            return False
        physical_label = cassette["physical_label"]
        cassette_number = tape["cassette_number"]
        return bool(
            isinstance(physical_label, str)
            and physical_label
            and isinstance(cassette_number, str)
            and cassette_number
            and physical_label.casefold() == cassette_number.casefold()
            and isinstance(tape["filesystem"], str)
            and tape["filesystem"].casefold() == "ltfs"
            and tape["status"] == "active"
        )

    @staticmethod
    def _completed_timestamps_valid(cassette, blocks) -> bool:
        if not blocks or any(block is None for block in blocks):
            return False
        cassette_started = MigrationValidator._timestamp(cassette["started_at"])
        cassette_completed = MigrationValidator._timestamp(cassette["completed_at"])
        if (
            cassette_started is None
            or cassette_completed is None
            or cassette_started > cassette_completed
        ):
            return False
        for block in blocks:
            block_started = MigrationValidator._timestamp(block["started_at"])
            block_completed = MigrationValidator._timestamp(block["completed_at"])
            if (
                block_started is None
                or block_completed is None
                or block_started > block_completed
            ):
                return False
        return True

    @staticmethod
    def _completed_totals_match(
        versions,
        blocks,
        cassette,
        planned_files,
        planned_bytes,
        copied_files,
        copied_bytes,
    ) -> bool:
        if (
            not blocks
            or any(block is None for block in blocks)
            or None in {planned_files, planned_bytes, copied_files, copied_bytes}
        ):
            return False
        if copied_files != planned_files or copied_bytes != planned_bytes:
            return False
        if any(
            row["visible"] != 1
            or not MigrationValidator._same_catalog_identifier(
                row["tape_id"], cassette["tape_id"]
            )
            or MigrationValidator._nonnegative_integer(row["size"]) is None
            or MigrationValidator._nonnegative_integer(row["mtime_ns"]) is None
            for row in versions
        ):
            return False
        if (
            len(versions) != copied_files
            or sum(row["size"] for row in versions) != copied_bytes
        ):
            return False
        versions_by_block: dict[str, list[sqlite3.Row]] = defaultdict(list)
        for row in versions:
            versions_by_block[row["block_id"]].append(row)
        return all(
            len(versions_by_block[block["id"]]) == block["copied_files"]
            and sum(row["size"] for row in versions_by_block[block["id"]])
            == block["copied_bytes"]
            for block in blocks
        )

    @staticmethod
    def _completed_manifest_matches(
        blocks_by_id, block_ids, versions, planned_files, planned_bytes
    ) -> bool:
        if not block_ids or planned_files is None or planned_bytes is None:
            return False
        if len(versions) != planned_files:
            return False
        for row in versions:
            block = blocks_by_id.get(row["block_id"])
            if block is None or row["block_id"] not in block_ids:
                return False
            root = block["tape_relative_root"]
            relative_path = row["relative_path"]
            tape_relative_path = row["tape_relative_path"]
            sha256 = row["sha256"]
            if (
                not isinstance(root, str)
                or not MigrationValidator._is_safe_relative_path(root)
                or not isinstance(row["library_id"], str)
                or not isinstance(block["library_id"], str)
                or row["library_id"].casefold() != block["library_id"].casefold()
                or not isinstance(relative_path, str)
                or not MigrationValidator._is_safe_relative_path(relative_path)
                or not isinstance(tape_relative_path, str)
                or not MigrationValidator._is_safe_relative_path(tape_relative_path)
                or tape_relative_path
                != (
                    PurePosixPath(root)
                    / "files"
                    / PurePosixPath(ltfs_tape_relative_path(relative_path))
                ).as_posix()
                or not isinstance(sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
                or MigrationValidator._nonnegative_integer(row["size"]) is None
                or MigrationValidator._nonnegative_integer(row["mtime_ns"]) is None
            ):
                return False
        return sum(row["size"] for row in versions) == planned_bytes

    @staticmethod
    def _block_ids(value: object) -> tuple[str, ...]:
        if not isinstance(value, str) or not value:
            return ()
        parts = value.split(",")
        if any(not part or part != part.strip() for part in parts):
            return ()
        return tuple(parts)

    @staticmethod
    def _is_pristine_cassette(cassette) -> bool:
        return not any(
            (
                cassette["status"] != "pending",
                cassette["tape_id"] is not None,
                cassette["block_id"] is not None,
                MigrationValidator._nonnegative_integer(cassette["copied_files"]) != 0,
                MigrationValidator._nonnegative_integer(cassette["copied_bytes"]) != 0,
                cassette["started_at"] is not None,
                cassette["completed_at"] is not None,
                cassette["error"] is not None,
            )
        )

    @staticmethod
    def _is_safe_relative_path(path: str) -> bool:
        posix_path = PurePosixPath(path)
        windows_path = PureWindowsPath(path)
        return bool(
            path
            and path != "."
            and "\x00" not in path
            and "\\" not in path
            and not posix_path.is_absolute()
            and not windows_path.is_absolute()
            and not windows_path.drive
            and not windows_path.root
            and ".." not in posix_path.parts
            and str(posix_path) == path
        )

    @staticmethod
    def _timestamp(value: object) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return parsed if parsed.tzinfo is not None else None

    @staticmethod
    def _nonnegative_integer(value: object) -> int | None:
        return value if type(value) is int and value >= 0 else None

    @staticmethod
    def _positive_integer(value: object) -> int | None:
        return value if type(value) is int and value > 0 else None

    @staticmethod
    def _same_catalog_identifier(left: object, right: object) -> bool:
        return bool(
            isinstance(left, str)
            and left
            and isinstance(right, str)
            and right
            and left.casefold() == right.casefold()
        )

    @staticmethod
    def _canonical_assignment(row: sqlite3.Row) -> dict[str, object]:
        return {
            "sequence": MigrationValidator._nonnegative_integer(row["sequence"]),
            "item_sequence": MigrationValidator._nonnegative_integer(
                row["item_sequence"]
            ),
            "library_id": row["library_id"]
            if isinstance(row["library_id"], str)
            else None,
            "relative_path": row["relative_path"]
            if isinstance(row["relative_path"], str)
            else None,
            "size": MigrationValidator._nonnegative_integer(row["size"]),
            "mtime_ns": MigrationValidator._nonnegative_integer(row["mtime_ns"]),
        }

    @staticmethod
    def _next_sequence(cassettes) -> int | None:
        pending = [
            sequence
            for row in cassettes
            if row["status"] != "completed"
            if (sequence := MigrationValidator._nonnegative_integer(row["sequence"]))
            is not None
        ]
        return pending[0] if pending else None
