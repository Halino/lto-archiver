"""Machine-safe offline migration command line interface."""

from __future__ import annotations

import argparse
import errno
import json
import os
import re
import stat
import sys
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import Path

from ltobackup.linux_settings import LinuxPaths

from . import importer as importer_module
from .archive import VerifiedBundle, read_bundle
from .importer import MigrationImporter, PathMappings
from .models import MigrationRejected
from .normalizer import normalize_capture

EXIT_ACCEPTED = 0
EXIT_REJECTED = 2
EXIT_RUNTIME_FAILURE = 3

_MAPPING_KEYS = frozenset({"library_roots", "device_names", "mount_paths"})
_MAX_MAPPING_BYTES = 1024 * 1024
_MAX_MAPPING_ITEMS = 256
_MAX_MAPPING_TEXT = 4096
_SAFE_ERROR_CODE = re.compile(r"[a-z0-9][a-z0-9-]{0,127}")


class _ArgumentRejected(Exception):
    pass


class _StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise _ArgumentRejected


class _DuplicateJsonKey(ValueError):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = _StrictArgumentParser(prog="lto-archiver-migrate", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)

    normalize = commands.add_parser("normalize", allow_abbrev=False)
    normalize.add_argument("capture", type=Path)
    normalize.add_argument("--expected-sha256", required=True)
    normalize.add_argument("--output", type=Path, required=True)
    normalize.add_argument("--json", action="store_true")

    inspect = commands.add_parser("inspect", allow_abbrev=False)
    inspect.add_argument("bundle", type=Path)
    inspect.add_argument("--json", action="store_true")

    import_command = commands.add_parser("import", allow_abbrev=False)
    import_command.add_argument("bundle", type=Path)
    import_command.add_argument("--mapping-file", type=Path, required=True)
    import_command.add_argument("--state-dir", type=Path, required=True)
    import_command.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
    except _ArgumentRejected:
        _emit_rejection(("invalid-arguments",))
        return EXIT_REJECTED

    try:
        if arguments.command == "normalize":
            bundle = normalize_capture(
                arguments.capture,
                arguments.output,
                expected_archive_sha256=arguments.expected_sha256,
            )
            result = _bundle_result(bundle)
        elif arguments.command == "inspect":
            result = _bundle_result(read_bundle(arguments.bundle))
        elif arguments.command == "import":
            result = _import_result(
                arguments.bundle,
                arguments.mapping_file,
                arguments.state_dir,
            )
        else:  # pragma: no cover - argparse owns the closed command set.
            raise MigrationRejected("command-invalid")
    except MigrationRejected as exc:
        _emit_rejection(_safe_rejection_codes(exc))
        return EXIT_REJECTED
    except Exception:  # noqa: BLE001 - the CLI boundary must redact runtime failures.
        _emit_runtime_failure()
        return EXIT_RUNTIME_FAILURE

    _emit_json(result)
    return EXIT_ACCEPTED


def _bundle_result(bundle: VerifiedBundle) -> dict[str, object]:
    report = bundle.acceptance
    report.require_valid()
    return {
        "accepted": True,
        "assignment_sha256": report.assignment_sha256,
        "bundle_sha256": bundle.bundle_sha256,
        "catalog_sha256": bundle.catalog_sha256,
        "completed_sequences": list(report.completed_sequences),
        "error_codes": [],
        "media_accesses": list(report.media_accesses),
        "next_sequence": report.next_sequence,
        "total_cassettes": report.total_cassettes,
    }


def _import_result(
    bundle_path: Path,
    mapping_path: Path,
    state_dir: Path,
) -> dict[str, object]:
    mappings = _read_mappings(mapping_path)
    state_dir = _absolute_state_dir(state_dir)
    paths = LinuxPaths.for_root(
        state_dir,
        state_dir.parent / ".lto-archiver-offline.sock",
    )
    verified = read_bundle(bundle_path)
    receipt = importer_module.build_import_acceptance_receipt(verified, mappings)
    report = MigrationImporter().import_bundle(
        verified,
        paths,
        mappings,
        acceptance_receipt=receipt,
    )
    if report != verified.acceptance:
        raise MigrationRejected("activated-state-invalid")
    result = json.loads(receipt)
    if not isinstance(result, dict):  # pragma: no cover - internal canonical builder.
        raise MigrationRejected("acceptance-receipt-invalid")
    return result


def _absolute_state_dir(value: Path) -> Path:
    path = Path(value)
    text = str(path)
    if not path.is_absolute() or not _safe_mapping_text(text):
        raise MigrationRejected("state-dir-invalid")
    return path


def _read_mappings(path: Path) -> PathMappings:
    payload = _read_mapping_bytes(Path(path))
    try:
        raw = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise MigrationRejected("mapping-invalid") from exc
    if not isinstance(raw, dict) or set(raw) != _MAPPING_KEYS:
        raise MigrationRejected("mapping-invalid")
    categories: dict[str, dict[str, str]] = {}
    total_items = 0
    for category in sorted(_MAPPING_KEYS):
        values = raw[category]
        if not isinstance(values, dict):
            raise MigrationRejected("mapping-invalid")
        total_items += len(values)
        if total_items > _MAX_MAPPING_ITEMS:
            raise MigrationRejected("mapping-size-limit")
        admitted: dict[str, str] = {}
        for source, destination in values.items():
            if (
                not isinstance(source, str)
                or not isinstance(destination, str)
                or not _safe_mapping_text(source)
                or not _safe_mapping_text(destination)
            ):
                raise MigrationRejected("mapping-invalid")
            admitted[source] = destination
        categories[category] = admitted
    return PathMappings(
        library_roots=categories["library_roots"],
        device_names=categories["device_names"],
        mount_paths=categories["mount_paths"],
    )


def _read_mapping_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        code = (
            "mapping-not-regular" if exc.errno == errno.ELOOP else "mapping-unreadable"
        )
        raise MigrationRejected(code) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise MigrationRejected("mapping-not-regular")
        if before.st_size > _MAX_MAPPING_BYTES:
            raise MigrationRejected("mapping-size-limit")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(_MAX_MAPPING_BYTES + 1)
        after = os.fstat(descriptor)
        if len(payload) > _MAX_MAPPING_BYTES:
            raise MigrationRejected("mapping-size-limit")
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(payload) != before.st_size:
            raise MigrationRejected("mapping-changed-during-read")
        return payload
    finally:
        os.close(descriptor)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(value)


def _safe_mapping_text(value: str) -> bool:
    return bool(
        value
        and len(value) <= _MAX_MAPPING_TEXT
        and all(
            not unicodedata.category(character).startswith("C") for character in value
        )
    )


def _safe_rejection_codes(exception: MigrationRejected) -> tuple[str, ...]:
    values = tuple(part for part in str(exception).split(",") if part)
    if values and all(_SAFE_ERROR_CODE.fullmatch(value) for value in values):
        return values
    return ("migration-rejected",)


def _rejection_payload(error_codes: Sequence[str]) -> dict[str, object]:
    return {
        "accepted": False,
        "error_codes": list(error_codes),
        "media_accesses": [],
    }


def _emit_rejection(error_codes: Sequence[str]) -> None:
    _emit_json(_rejection_payload(error_codes))
    sys.stderr.write("migration rejected\n")


def _emit_runtime_failure() -> None:
    _emit_json(_rejection_payload(("runtime-failure",)))
    sys.stderr.write("migration failed\n")


def _emit_json(value: Mapping[str, object]) -> None:
    sys.stdout.write(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    )


if __name__ == "__main__":
    raise SystemExit(main())
