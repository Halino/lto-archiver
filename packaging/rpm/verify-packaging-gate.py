#!/usr/bin/python3.11
"""Verify signed repository-test evidence before an RPM release build."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_FINGERPRINT = re.compile(r"[0-9A-F]{40}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PUBLIC_KEY_SHA256 = "0363930f5a9c9b6a11f8891b498de9381233d63fdf49ea71bfe8313ed4501804"
_REPORT_FIELDS = {
    "builder_sha256",
    "python",
    "repository_commit",
    "runner_sha256",
    "schema_version",
    "skipped_test_ids",
    "status",
    "test_command",
    "test_module",
    "tests_run",
}
_ALLOWED_SKIPS = frozenset(
    {
        "tests.test_linux_packaging.LinuxPackagingTests."
        "test_built_rpm_payload_and_ltfs_info_dependency_when_provided"
    }
)
_ALLOWED_VERIFY_STATUS = frozenset(
    {
        "GOODSIG",
        "KEY_CONSIDERED",
        "NEWSIG",
        "SIG_ID",
        "TRUST_FULLY",
        "TRUST_MARGINAL",
        "TRUST_NEVER",
        "TRUST_ULTIMATE",
        "TRUST_UNDEFINED",
        "VALIDSIG",
    }
)


class GateError(RuntimeError):
    """The packaging gate evidence is invalid or unauthenticated."""


@dataclass(frozen=True)
class GateTools:
    gpg: Path = Path("/usr/bin/gpg")


def _open_validated(path: Path, *, owner_only: bool) -> int:
    try:
        path_status = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        status = os.fstat(descriptor)
    except OSError as error:
        raise GateError from error
    forbidden_mode = 0o077 if owner_only else 0o022
    if (
        not path.is_absolute()
        or not stat.S_ISREG(path_status.st_mode)
        or not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or status.st_uid != os.getuid()
        or status.st_mode & forbidden_mode
        or (path_status.st_dev, path_status.st_ino)
        != (status.st_dev, status.st_ino)
    ):
        os.close(descriptor)
        raise GateError
    return descriptor


def _validated_tool(path: Path) -> str:
    try:
        status = path.lstat()
    except OSError as error:
        raise GateError from error
    if (
        not path.is_absolute()
        or not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or status.st_mode & 0o022
        or not status.st_mode & stat.S_IXUSR
        or status.st_uid not in (0, os.getuid())
    ):
        raise GateError
    return os.fspath(path)


def _sha256_descriptor(descriptor: int) -> str:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as error:
        raise GateError from error


def _open_output_directory(path: Path) -> int:
    try:
        path_status = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        status = os.fstat(descriptor)
    except OSError as error:
        raise GateError from error
    if (
        not path.is_absolute()
        or not stat.S_ISDIR(path_status.st_mode)
        or not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) != 0o700
        or (path_status.st_dev, path_status.st_ino)
        != (status.st_dev, status.st_ino)
    ):
        os.close(descriptor)
        raise GateError
    return descriptor


def _materialize_descriptor(source: int, directory: int, name: str) -> None:
    destination = -1
    created = False
    complete = False
    try:
        destination = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o400,
            dir_fd=directory,
        )
        created = True
        os.lseek(source, 0, os.SEEK_SET)
        while chunk := os.read(source, 1024 * 1024):
            view = memoryview(chunk)
            while view:
                written = os.write(destination, view)
                if written <= 0:
                    raise GateError
                view = view[written:]
        os.fchmod(destination, 0o444)
        os.fsync(destination)
        status = os.fstat(destination)
        path_status = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or status.st_nlink != 1
            or stat.S_IMODE(status.st_mode) != 0o444
            or (path_status.st_dev, path_status.st_ino)
            != (status.st_dev, status.st_ino)
        ):
            raise GateError
        complete = True
    except (OSError, ValueError) as error:
        raise GateError from error
    finally:
        if destination >= 0:
            os.close(destination)
        if created and not complete:
            with contextlib.suppress(OSError):
                os.unlink(name, dir_fd=directory)


def _materialize_verified_evidence(
    output_directory: Path, report_fd: int, signature_fd: int
) -> None:
    directory = _open_output_directory(output_directory)
    try:
        _materialize_descriptor(report_fd, directory, "packaging-gate.json")
        _materialize_descriptor(
            signature_fd, directory, "packaging-gate.json.asc"
        )
        os.fsync(directory)
    except BaseException:
        for name in ("packaging-gate.json", "packaging-gate.json.asc"):
            with contextlib.suppress(OSError):
                os.unlink(name, dir_fd=directory)
        raise
    finally:
        os.close(directory)


def _run(
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    run_command: Callable[..., subprocess.CompletedProcess[bytes]],
    pass_fds: Sequence[int] = (),
) -> bytes:
    try:
        result = run_command(
            list(command),
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            close_fds=True,
            pass_fds=tuple(pass_fds),
        )
    except (OSError, subprocess.SubprocessError, TypeError, ValueError) as error:
        raise GateError from error
    stdout = bytes(getattr(result, "stdout", b"") or b"")
    stderr = bytes(getattr(result, "stderr", b"") or b"")
    if result.returncode != 0 or len(stdout) > 1024 * 1024 or len(stderr) > 65536:
        raise GateError
    return stdout


def _public_key_records(output: bytes) -> dict[str, tuple[str, int, str, str, int, str]]:
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeError as error:
        raise GateError from error
    records: dict[str, tuple[str, int, str, str, int, str]] = {}
    pending: tuple[str, int, str, str, int, str] | None = None
    for line in lines:
        fields = line.split(":")
        if fields[0] in {"pub", "sub"}:
            try:
                pending = (
                    fields[0],
                    int(fields[2]),
                    fields[3],
                    fields[1],
                    int(fields[6] or "0"),
                    "".join(fields[11:13]).lower(),
                )
            except (IndexError, ValueError) as error:
                raise GateError from error
        elif fields[0] == "fpr" and len(fields) > 9 and pending is not None:
            fingerprint = fields[9]
            if _FINGERPRINT.fullmatch(fingerprint) is None or fingerprint in records:
                raise GateError
            records[fingerprint] = pending
            pending = None
    return records


def _load_report(
    descriptor: int,
    *,
    expected_commit: str,
    expected_builder_sha256: str,
    expected_runner_sha256: str,
) -> dict[str, Any]:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read()
        payload = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateError from error
    canonical = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    if (
        type(payload) is not dict
        or set(payload) != _REPORT_FIELDS
        or raw != canonical
        or payload["schema_version"] != 1
        or payload["status"] != "passed"
        or payload["test_module"] != "tests.test_linux_packaging"
        or payload["test_command"] != "tests.test_linux_packaging"
        or payload["python"] != "/usr/bin/python3.11 -I"
        or payload["repository_commit"] != expected_commit
        or payload["builder_sha256"] != expected_builder_sha256
        or payload["runner_sha256"] != expected_runner_sha256
        or _COMMIT.fullmatch(str(payload["repository_commit"])) is None
        or _SHA256.fullmatch(str(payload["builder_sha256"])) is None
        or _SHA256.fullmatch(str(payload["runner_sha256"])) is None
        or type(payload["tests_run"]) is not int
        or payload["tests_run"] <= 0
        or type(payload["skipped_test_ids"]) is not list
        or payload["skipped_test_ids"] != sorted(set(payload["skipped_test_ids"]))
        or not set(payload["skipped_test_ids"]).issubset(_ALLOWED_SKIPS)
        or any(
            type(test_id) is not str
            or not test_id.startswith("tests.test_linux_packaging.")
            for test_id in payload["skipped_test_ids"]
        )
    ):
        raise GateError
    return payload


def _prepare_verification(
    report: Path,
    report_fd: int,
    public_key_fd: int,
    *,
    expected_commit: str,
    expected_builder_sha256: str,
    expected_runner_sha256: str,
    primary_fingerprint: str,
    signing_subkey_fingerprint: str,
    tools: GateTools,
    run_command: Callable[..., subprocess.CompletedProcess[bytes]],
) -> tuple[dict[str, Any], str, dict[str, str], Path]:
    payload = _load_report(
        report_fd,
        expected_commit=expected_commit,
        expected_builder_sha256=expected_builder_sha256,
        expected_runner_sha256=expected_runner_sha256,
    )
    if _sha256_descriptor(public_key_fd) != _PUBLIC_KEY_SHA256:
        raise GateError
    gpg = _validated_tool(Path(tools.gpg))
    base_env = {"LANG": "C", "LC_ALL": "C"}
    verification_home = Path(
        tempfile.mkdtemp(prefix=".lto-packaging-gate.", dir=report.parent)
    )
    verification_home.chmod(0o700)
    verify_env = {
        **base_env,
        "GNUPGHOME": os.fspath(verification_home),
    }
    try:
        public_records = _public_key_records(
            _run(
                (
                    gpg,
                    "--homedir",
                    os.fspath(verification_home),
                    "--batch",
                    "--with-colons",
                    "--show-keys",
                    f"/proc/self/fd/{public_key_fd}",
                ),
                env=verify_env,
                run_command=run_command,
                pass_fds=(public_key_fd,),
            )
        )
        if set(public_records) != {
            primary_fingerprint,
            signing_subkey_fingerprint,
        }:
            raise GateError
        for fingerprint, expected_type in (
            (primary_fingerprint, "pub"),
            (signing_subkey_fingerprint, "sub"),
        ):
            record_type, bits, algorithm, validity, expires, capabilities = (
                public_records[fingerprint]
            )
            if (
                record_type != expected_type
                or bits < 3072
                or algorithm != "1"
                or validity.lower() in {"d", "e", "r"}
                or (expires != 0 and expires <= int(time.time()))
                or (expected_type == "sub" and "s" not in capabilities)
            ):
                raise GateError
    except BaseException:
        shutil.rmtree(verification_home, ignore_errors=True)
        raise
    return payload, gpg, verify_env, verification_home


def verify_gate(
    report: Path,
    signature: Path,
    public_key: Path,
    *,
    verified_output_directory: Path,
    expected_commit: str,
    expected_builder_sha256: str,
    expected_runner_sha256: str,
    primary_fingerprint: str,
    signing_subkey_fingerprint: str,
    tools: GateTools | None = None,
    run_command: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> dict[str, Any]:
    tools = tools or GateTools()
    report = Path(report)
    signature = Path(signature)
    public_key = Path(public_key)
    verified_output_directory = Path(verified_output_directory)
    if (
        _COMMIT.fullmatch(expected_commit) is None
        or _SHA256.fullmatch(expected_builder_sha256) is None
        or _SHA256.fullmatch(expected_runner_sha256) is None
        or _FINGERPRINT.fullmatch(primary_fingerprint) is None
        or _FINGERPRINT.fullmatch(signing_subkey_fingerprint) is None
    ):
        raise GateError
    report_fd = _open_validated(report, owner_only=True)
    try:
        signature_fd = _open_validated(signature, owner_only=True)
    except BaseException:
        os.close(report_fd)
        raise
    try:
        public_key_fd = _open_validated(public_key, owner_only=False)
    except BaseException:
        os.close(signature_fd)
        os.close(report_fd)
        raise
    try:
        payload, gpg, verify_env, verification_home = _prepare_verification(
            report,
            report_fd,
            public_key_fd,
            expected_commit=expected_commit,
            expected_builder_sha256=expected_builder_sha256,
            expected_runner_sha256=expected_runner_sha256,
            primary_fingerprint=primary_fingerprint,
            signing_subkey_fingerprint=signing_subkey_fingerprint,
            tools=tools,
            run_command=run_command,
        )
    except BaseException:
        os.close(public_key_fd)
        os.close(signature_fd)
        os.close(report_fd)
        raise
    try:
        _run(
            (
                gpg,
                "--homedir",
                os.fspath(verification_home),
                "--batch",
                "--import",
                f"/proc/self/fd/{public_key_fd}",
            ),
            env=verify_env,
            run_command=run_command,
            pass_fds=(public_key_fd,),
        )
        status_output = _run(
            (
                gpg,
                "--homedir",
                os.fspath(verification_home),
                "--batch",
                "--status-fd=1",
                "--verify",
                f"/proc/self/fd/{signature_fd}",
                f"/proc/self/fd/{report_fd}",
            ),
            env=verify_env,
            run_command=run_command,
            pass_fds=(signature_fd, report_fd),
        )
        try:
            status_rows = [
                line.decode("ascii").split()
                for line in status_output.splitlines()
                if line.startswith(b"[GNUPG:] ")
            ]
            signatures = [
                row
                for row in status_rows
                if len(row) > 1 and row[1] == "VALIDSIG"
            ]
        except UnicodeError as error:
            raise GateError from error
        if (
            any(
                len(row) < 2 or row[1] not in _ALLOWED_VERIFY_STATUS
                for row in status_rows
            )
            or len(signatures) != 1
            or len(signatures[0]) != 12
            or signatures[0][2] != signing_subkey_fingerprint
            or signatures[0][9] != "8"
            or signatures[0][11] != primary_fingerprint
        ):
            raise GateError
        _materialize_verified_evidence(
            verified_output_directory, report_fd, signature_fd
        )
    finally:
        shutil.rmtree(verification_home, ignore_errors=True)
        os.close(public_key_fd)
        os.close(signature_fd)
        os.close(report_fd)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--verified-output-directory", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-builder-sha256", required=True)
    parser.add_argument("--expected-runner-sha256", required=True)
    parser.add_argument("--primary-fingerprint", required=True)
    parser.add_argument("--signing-subkey-fingerprint", required=True)
    try:
        args = parser.parse_args(argv)
        verify_gate(
            args.report,
            args.signature,
            args.public_key,
            verified_output_directory=args.verified_output_directory,
            expected_commit=args.expected_commit,
            expected_builder_sha256=args.expected_builder_sha256,
            expected_runner_sha256=args.expected_runner_sha256,
            primary_fingerprint=args.primary_fingerprint,
            signing_subkey_fingerprint=args.signing_subkey_fingerprint,
        )
        return 0
    except (GateError, OSError, TypeError, ValueError):
        with contextlib.suppress(OSError):
            sys.stderr.write("RPM packaging gate verification failed\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
