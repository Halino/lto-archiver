"""Minimal trusted-local administrator client for cassette-four cutover."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from pydantic import ValidationError

from .client import UnixDaemonClient
from .daemon.api_models import (
    CutoverAuthorizationRequestV1,
    SignedAcceptanceReportV1,
)

_MAX_FILE_BYTES = 64 * 1024
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_JOB_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class _Rejected(RuntimeError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise _Rejected()


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="lto-archiver-admin", allow_abbrev=False)
    parser.add_argument(
        "--socket",
        type=Path,
        default=Path("/run/lto-archiver/daemon.sock"),
    )
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    commands = parser.add_subparsers(dest="group", required=True)

    cutover = commands.add_parser("cutover", allow_abbrev=False)
    cutover_commands = cutover.add_subparsers(dest="command", required=True)
    prepare = cutover_commands.add_parser("prepare", allow_abbrev=False)
    prepare.add_argument("job_id")
    prepare.add_argument("--report-file", type=Path, required=True)
    authorize = cutover_commands.add_parser("authorize", allow_abbrev=False)
    authorize.add_argument("--report", type=Path, required=True)
    authorize.add_argument("--authorization-file", type=Path, required=True)
    authorize.add_argument("--idempotency-key", required=True)

    job = commands.add_parser("job", allow_abbrev=False)
    job_commands = job.add_subparsers(dest="command", required=True)
    resume = job_commands.add_parser("resume", allow_abbrev=False)
    resume.add_argument("job_id")
    resume.add_argument("--authorization-file", type=Path, required=True)
    resume.add_argument("--confirm-format-label", required=True)
    resume.add_argument("--idempotency-key", required=True)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    client_factory: Callable[..., UnixDaemonClient] = UnixDaemonClient,
) -> int:
    try:
        arguments = _parser().parse_args(argv)
        if not arguments.socket.is_absolute():
            raise _Rejected()
        idempotency_key = getattr(arguments, "idempotency_key", None)
        if idempotency_key is not None and not _SAFE_IDENTIFIER.fullmatch(
            idempotency_key
        ):
            raise _Rejected()
        with client_factory(arguments.socket, arguments.timeout_seconds) as client:
            if arguments.group == "cutover" and arguments.command == "prepare":
                result = _prepare(arguments, client)
            elif arguments.group == "cutover" and arguments.command == "authorize":
                result = _authorize(arguments, client)
            elif arguments.group == "job" and arguments.command == "resume":
                result = _resume(arguments, client)
            else:  # pragma: no cover - argparse owns the closed command set.
                raise _Rejected()
    except Exception:  # noqa: BLE001 - CLI boundary never emits secret-bearing errors.
        print('{"error":{"code":"admin_command_failed"}}', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


def _prepare(arguments, client) -> dict[str, object]:
    if not _SAFE_JOB_ID.fullmatch(arguments.job_id):
        raise _Rejected()
    report = client.get(
        f"/api/v1/jobs/{arguments.job_id}/cutover/cassette-4/report",
        response_model=SignedAcceptanceReportV1,
        principal="local-admin",
    )
    _write_authorization_file(
        Path(arguments.report_file), report.model_dump(mode="json")
    )
    return {
        "accepted": True,
        "job_id": report.job_id,
        "report_file": str(arguments.report_file),
    }


def _authorize(arguments, client) -> dict[str, object]:
    try:
        report = SignedAcceptanceReportV1.model_validate(
            _read_json(arguments.report, require_private=False)
        )
    except ValidationError as exc:
        raise _Rejected() from exc
    report_payload = report.model_dump(mode="json")
    report_sha256 = hashlib.sha256(
        json.dumps(
            report_payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    authorization_path = Path(arguments.authorization_file)
    if authorization_path.exists():
        pending = _read_json(authorization_path, require_private=True)
        expected_keys = {
            "version",
            "state",
            "job_id",
            "expected_label",
            "cutover_credential",
            "idempotency_key",
            "acceptance_report_sha256",
        }
        credential = pending.get("cutover_credential")
        if (
            set(pending) != expected_keys
            or pending.get("version") != 1
            or pending.get("state") not in {"pending", "accepted"}
            or pending.get("job_id") != report.job_id
            or pending.get("expected_label") != report.expected_label
            or pending.get("idempotency_key") != arguments.idempotency_key
            or pending.get("acceptance_report_sha256") != report_sha256
            or not isinstance(credential, str)
            or len(credential) < 32
        ):
            raise _Rejected()
    else:
        credential = secrets.token_urlsafe(32)
        pending = {
            "version": 1,
            "state": "pending",
            "job_id": report.job_id,
            "expected_label": report.expected_label,
            "cutover_credential": credential,
            "idempotency_key": arguments.idempotency_key,
            "acceptance_report_sha256": report_sha256,
        }
        _write_authorization_file(authorization_path, pending)
    request = CutoverAuthorizationRequestV1(
        acceptance_report=report,
        credential_sha256=hashlib.sha256(credential.encode("utf-8")).hexdigest(),
    )
    operation = client.post(
        "/api/v1/cutover/cassette-4/authorizations",
        request.model_dump(mode="json"),
        arguments.idempotency_key,
        principal="local-admin",
    )
    if (
        operation.get("state") != "succeeded"
        or operation.get("kind") != "cutover.authorize"
    ):
        raise _Rejected()
    accepted = dict(pending)
    accepted["state"] = "accepted"
    _replace_authorization_file(authorization_path, accepted)
    return {
        "accepted": True,
        "authorization_file": str(arguments.authorization_file),
        "operation_id": operation.get("id"),
    }


def _resume(arguments, client) -> dict[str, object]:
    if not _SAFE_JOB_ID.fullmatch(arguments.job_id):
        raise _Rejected()
    authorization = _read_json(arguments.authorization_file, require_private=True)
    if set(authorization) != {
        "version",
        "state",
        "job_id",
        "expected_label",
        "cutover_credential",
        "idempotency_key",
        "acceptance_report_sha256",
    }:
        raise _Rejected()
    credential = authorization["cutover_credential"]
    if (
        authorization["version"] != 1
        or authorization["state"] != "accepted"
        or authorization["job_id"] != arguments.job_id
        or authorization["expected_label"] != arguments.confirm_format_label
        or not isinstance(credential, str)
        or len(credential) < 32
    ):
        raise _Rejected()
    operation = client.post(
        f"/api/v1/jobs/{arguments.job_id}/resume",
        {
            "cutover_credential": credential,
            "format_confirmation_label": arguments.confirm_format_label,
        },
        arguments.idempotency_key,
        principal="local-admin",
    )
    if operation.get("kind") != "archive.resume":
        raise _Rejected()
    return {
        "accepted": True,
        "operation_id": operation.get("id"),
        "state": operation.get("state"),
    }


def _read_json(path: Path, *, require_private: bool) -> dict:
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > _MAX_FILE_BYTES
            or (require_private and stat.S_IMODE(metadata.st_mode) != 0o600)
            or (require_private and metadata.st_uid != os.geteuid())
        ):
            raise _Rejected()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(_MAX_FILE_BYTES + 1)
        if len(payload) != metadata.st_size:
            raise _Rejected()
        value = json.loads(payload.decode("utf-8"))
    finally:
        os.close(descriptor)
    if not isinstance(value, dict):
        raise _Rejected()
    return value


def _write_authorization_file(path: Path, payload: dict[str, object]) -> None:
    path = Path(path)
    if not path.is_absolute():
        raise _Rejected()
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    _fsync_parent(path)


def _fsync_parent(path: Path) -> None:
    directory = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _replace_authorization_file(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.accepted")
    try:
        _write_authorization_file(temporary, payload)
        os.replace(temporary, path)
        _fsync_parent(path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
