#!/usr/bin/python3.11
"""Create an atomically published, signed copy of one closed RPM release tree."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
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

_POLICY_FIELDS = {
    "accepted_digest_algorithms",
    "accepted_public_key_algorithm",
    "exact_package_names",
    "minimum_rsa_bits",
    "primary_fingerprint",
    "public_key_path",
    "public_key_sha256",
    "schema_version",
    "signing_subkey_fingerprint",
}
_FINGERPRINT = re.compile(r"[0-9A-F]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MAX_TOOL_OUTPUT = 1024 * 1024
_RENAME_NOREPLACE = 1


class SigningError(RuntimeError):
    """The release tree could not be signed under the closed policy."""


@dataclass(frozen=True)
class SigningTools:
    gpg: Path = Path("/usr/bin/gpg")
    rpm: Path = Path("/usr/bin/rpm")
    rpmkeys: Path = Path("/usr/bin/rpmkeys")
    rpmsign: Path = Path("/usr/bin/rpmsign")


def _rename_noreplace(
    source_fd: int,
    source_name: str,
    target_fd: int,
    target_name: str,
) -> None:
    """Atomically publish one directory without replacing an existing name."""
    for descriptor in (source_fd, target_fd):
        if type(descriptor) is not int or descriptor < 0:
            raise SigningError
    for name in (source_name, target_name):
        if not name or name in {".", ".."} or "/" in name:
            raise SigningError
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError) as error:
        raise SigningError from error
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            source_fd,
            os.fsencode(source_name),
            target_fd,
            os.fsencode(target_name),
            _RENAME_NOREPLACE,
        )
        != 0
    ):
        error_number = ctypes.get_errno()
        if error_number == 0:
            error_number = errno.EIO
        raise SigningError from OSError(error_number, os.strerror(error_number))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise SigningError from error
    return digest.hexdigest()


def _load_policy(path: Path) -> Mapping[str, Any]:
    try:
        status = path.lstat()
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SigningError from error
    if (
        not path.is_absolute()
        or not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or status.st_mode & 0o022
        or type(payload) is not dict
        or set(payload) != _POLICY_FIELDS
        or payload["schema_version"] != 1
        or payload["accepted_digest_algorithms"] != ["SHA256"]
        or payload["accepted_public_key_algorithm"] != "RSA"
        or type(payload["minimum_rsa_bits"]) is not int
        or payload["minimum_rsa_bits"] < 3072
        or type(payload["exact_package_names"]) is not list
        or not payload["exact_package_names"]
        or any(type(item) is not str or not item for item in payload["exact_package_names"])
        or _FINGERPRINT.fullmatch(str(payload["primary_fingerprint"])) is None
        or _FINGERPRINT.fullmatch(str(payload["signing_subkey_fingerprint"])) is None
        or _SHA256.fullmatch(str(payload["public_key_sha256"])) is None
        or not isinstance(payload["public_key_path"], str)
    ):
        raise SigningError
    return payload


def _validated_tool(path: Path) -> str:
    try:
        status = path.lstat()
    except OSError as error:
        raise SigningError from error
    if (
        not path.is_absolute()
        or not stat.S_ISREG(status.st_mode)
        or not status.st_mode & stat.S_IXUSR
        or status.st_mode & 0o022
        or status.st_uid not in (0, os.getuid())
    ):
        raise SigningError
    return os.fspath(path)


def _run(
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    run_command: Callable[..., subprocess.CompletedProcess[bytes]],
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
        )
    except (OSError, subprocess.SubprocessError, TypeError, ValueError) as error:
        raise SigningError from error
    stdout = bytes(getattr(result, "stdout", b"") or b"")
    stderr = bytes(getattr(result, "stderr", b"") or b"")
    if result.returncode != 0 or len(stdout) > _MAX_TOOL_OUTPUT or len(stderr) > 65536:
        raise SigningError
    return stdout


def _key_records(output: bytes) -> dict[str, tuple[str, int, str, str, int, str]]:
    try:
        lines = output.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise SigningError from error
    records: dict[str, tuple[str, int, str, str, int, str]] = {}
    pending: tuple[str, int, str, str, int, str] | None = None
    for line in lines:
        fields = line.split(":")
        if fields[0] in {"pub", "sub", "sec", "ssb"}:
            try:
                pending = (
                    fields[3],
                    int(fields[2]),
                    fields[0],
                    fields[1],
                    int(fields[6] or "0"),
                    "".join(fields[11:13]).lower(),
                )
            except (IndexError, ValueError) as error:
                raise SigningError from error
        elif fields[0] == "fpr" and pending is not None:
            try:
                fingerprint = fields[9]
            except IndexError as error:
                raise SigningError from error
            if _FINGERPRINT.fullmatch(fingerprint) is None or fingerprint in records:
                raise SigningError
            records[fingerprint] = pending
            pending = None
    return records


def _validate_tree(root: Path) -> set[str]:
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise SigningError
    regular: set[str] = set()
    try:
        for directory, names, files in os.walk(root, topdown=True, followlinks=False):
            base = Path(directory)
            for name in names:
                status = (base / name).lstat()
                if not stat.S_ISDIR(status.st_mode) or stat.S_ISLNK(status.st_mode):
                    raise SigningError
            for name in files:
                path = base / name
                status = path.lstat()
                if (
                    not stat.S_ISREG(status.st_mode)
                    or status.st_nlink != 1
                    or status.st_mode & 0o022
                ):
                    raise SigningError
                regular.add(path.relative_to(root).as_posix())
    except OSError as error:
        raise SigningError from error
    return regular


def _manifest_rows(root: Path, *, exclude_signature: bool) -> list[str]:
    files = _validate_tree(root)
    excluded = {"SHA256SUMS"}
    if exclude_signature:
        excluded.add("SHA256SUMS.asc")
    rows = []
    for relative in sorted(files - excluded):
        if "\n" in relative or "\r" in relative or "\\" in relative:
            raise SigningError
        rows.append(f"{_sha256(root / relative)}  {relative}\n")
    return rows


def _verify_unsigned_manifest(root: Path) -> None:
    manifest = root / "SHA256SUMS"
    try:
        payload = manifest.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise SigningError from error
    expected = "".join(_manifest_rows(root, exclude_signature=False))
    if (
        payload != expected
        or (root / "SHA256SUMS.asc").exists()
        or (root / "SIGNING.json").exists()
    ):
        raise SigningError


def _rpm_closure(root: Path) -> tuple[Path, Path]:
    binaries = sorted((root / "RPMS").rglob("*.rpm")) if (root / "RPMS").is_dir() else []
    sources = sorted((root / "SRPMS").rglob("*.rpm")) if (root / "SRPMS").is_dir() else []
    if (
        len(binaries) != 1
        or len(sources) != 1
        or set(root.rglob("*.rpm")) != {binaries[0], sources[0]}
    ):
        raise SigningError
    return binaries[0], sources[0]


def _atomic_write(path: Path, content: bytes, mode: int = 0o644) -> None:
    temporary = path.with_name(f".{path.name}.new")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            mode,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as error:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise SigningError from error


@contextlib.contextmanager
def _staged_rpm_write_access(path: Path):
    """Permit signing one staged RPM, including RPM's atomic replacement."""
    parent_descriptor = -1
    original_descriptor = -1
    signed_descriptor = -1
    try:
        parent_path_status = path.parent.lstat()
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        parent_status = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent_path_status.st_mode)
            or (parent_path_status.st_dev, parent_path_status.st_ino)
            != (parent_status.st_dev, parent_status.st_ino)
        ):
            raise SigningError
        leaf_status = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        original_descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        original_status = os.fstat(original_descriptor)
        if (
            not stat.S_ISREG(leaf_status.st_mode)
            or not stat.S_ISREG(original_status.st_mode)
            or leaf_status.st_nlink != 1
            or original_status.st_nlink != 1
            or original_status.st_uid != os.getuid()
            or original_status.st_mode & 0o022
            or (leaf_status.st_dev, leaf_status.st_ino)
            != (original_status.st_dev, original_status.st_ino)
        ):
            raise SigningError
        os.fchmod(original_descriptor, 0o600)
        writable_status = os.fstat(original_descriptor)
        if stat.S_IMODE(writable_status.st_mode) != 0o600:
            raise SigningError
        yield

        current_parent_path_status = path.parent.lstat()
        if (
            current_parent_path_status.st_dev,
            current_parent_path_status.st_ino,
        ) != (parent_status.st_dev, parent_status.st_ino):
            raise SigningError
        signed_descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        signed_status = os.fstat(signed_descriptor)
        signed_leaf_status = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        original_after_sign = os.fstat(original_descriptor)
        same_inode = (
            signed_status.st_dev,
            signed_status.st_ino,
        ) == (original_after_sign.st_dev, original_after_sign.st_ino)
        if (
            not stat.S_ISREG(signed_leaf_status.st_mode)
            or not stat.S_ISREG(signed_status.st_mode)
            or signed_leaf_status.st_nlink != 1
            or signed_status.st_nlink != 1
            or signed_status.st_uid != os.getuid()
            or stat.S_IMODE(signed_status.st_mode) != 0o600
            or (signed_leaf_status.st_dev, signed_leaf_status.st_ino)
            != (signed_status.st_dev, signed_status.st_ino)
            or (not same_inode and original_after_sign.st_nlink != 0)
        ):
            raise SigningError
        os.fchmod(signed_descriptor, 0o444)
        os.fsync(signed_descriptor)
        if not same_inode:
            os.fchmod(original_descriptor, 0o444)
            os.fsync(original_descriptor)
        os.fsync(parent_descriptor)
        immutable_status = os.fstat(signed_descriptor)
        immutable_leaf_status = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            stat.S_IMODE(immutable_status.st_mode) != 0o444
            or stat.S_IMODE(immutable_leaf_status.st_mode) != 0o444
            or immutable_leaf_status.st_nlink != 1
            or (immutable_leaf_status.st_dev, immutable_leaf_status.st_ino)
            != (immutable_status.st_dev, immutable_status.st_ino)
        ):
            raise SigningError
    except OSError as error:
        raise SigningError from error
    finally:
        primary_error = sys.exception()
        restore_error: OSError | None = None
        if original_descriptor >= 0:
            try:
                os.fchmod(original_descriptor, 0o444)
                os.fsync(original_descriptor)
            except OSError as error:
                restore_error = error
        if signed_descriptor >= 0:
            os.close(signed_descriptor)
        if original_descriptor >= 0:
            os.close(original_descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        if restore_error is not None:
            if primary_error is not None:
                primary_error.add_note(
                    "also failed to restore the original staged RPM read-only"
                )
            else:
                raise SigningError from restore_error


def sign_tree(
    unsigned_tree: Path,
    output_tree: Path,
    *,
    package_name: str,
    gnupg_home: Path,
    primary_fingerprint: str,
    signing_subkey_fingerprint: str,
    policy_file: Path,
    public_key: Path,
    tools: SigningTools | None = None,
    run_command: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> dict[str, Any]:
    unsigned_tree = Path(unsigned_tree)
    output_tree = Path(output_tree)
    gnupg_home = Path(gnupg_home)
    policy_file = Path(policy_file)
    public_key = Path(public_key)
    if tools is None:
        tools = SigningTools()
    if (
        not output_tree.is_absolute()
        or ".." in output_tree.parts
        or output_tree.exists()
        or output_tree.is_symlink()
        or not output_tree.parent.is_dir()
        or output_tree.parent.is_symlink()
        or not gnupg_home.is_absolute()
        or ".." in gnupg_home.parts
        or gnupg_home.is_symlink()
        or not gnupg_home.is_dir()
        or gnupg_home.stat().st_mode & 0o077
        or _FINGERPRINT.fullmatch(primary_fingerprint) is None
        or _FINGERPRINT.fullmatch(signing_subkey_fingerprint) is None
    ):
        raise SigningError
    policy = _load_policy(policy_file)
    output_parent_identity = output_tree.parent.stat()
    if (
        package_name not in policy["exact_package_names"]
        or primary_fingerprint != policy["primary_fingerprint"]
        or signing_subkey_fingerprint != policy["signing_subkey_fingerprint"]
        or not public_key.is_absolute()
        or public_key.is_symlink()
        or _sha256(public_key) != policy["public_key_sha256"]
    ):
        raise SigningError
    tool_paths = {
        name: _validated_tool(Path(getattr(tools, name)))
        for name in ("gpg", "rpm", "rpmkeys", "rpmsign")
    }
    base_env = {"LANG": "C", "LC_ALL": "C"}
    signing_env = {**base_env, "GNUPGHOME": os.fspath(gnupg_home)}
    inspection_home = Path(
        tempfile.mkdtemp(prefix=".lto-signing-key-inspection.", dir=output_tree.parent)
    )
    inspection_home.chmod(0o700)
    try:
        inspection_env = {
            **base_env,
            "GNUPGHOME": os.fspath(inspection_home),
        }
        public_records = _key_records(
            _run(
                (
                    tool_paths["gpg"],
                    "--homedir",
                    os.fspath(inspection_home),
                    "--batch",
                    "--with-colons",
                    "--show-keys",
                    os.fspath(public_key),
                ),
                env=inspection_env,
                run_command=run_command,
            )
        )
    finally:
        shutil.rmtree(inspection_home, ignore_errors=True)
    secret_records = _key_records(
        _run(
            (
                tool_paths["gpg"],
                "--homedir",
                os.fspath(gnupg_home),
                "--batch",
                "--with-colons",
                "--list-secret-keys",
                primary_fingerprint,
            ),
            env=signing_env,
            run_command=run_command,
        )
    )
    minimum_bits = policy["minimum_rsa_bits"]
    for records in (public_records, secret_records):
        if set(records) != {primary_fingerprint, signing_subkey_fingerprint}:
            raise SigningError
        for fingerprint in (primary_fingerprint, signing_subkey_fingerprint):
            algorithm, bits, record_type, validity, expires, capabilities = records[
                fingerprint
            ]
            if (
                algorithm != "1"
                or bits < minimum_bits
                or validity.lower() in {"d", "e", "r"}
                or (expires != 0 and expires <= int(time.time()))
                or (
                    fingerprint == signing_subkey_fingerprint
                    and (record_type not in {"sub", "ssb"} or "s" not in capabilities)
                )
            ):
                raise SigningError

    _verify_unsigned_manifest(unsigned_tree)
    unsigned_binary, unsigned_source = _rpm_closure(unsigned_tree)
    unsigned_manifest_sha256 = _sha256(unsigned_tree / "SHA256SUMS")
    unsigned_rpm_sha256 = [
        {"kind": "binary", "sha256": _sha256(unsigned_binary)},
        {"kind": "source", "sha256": _sha256(unsigned_source)},
    ]
    staging_root = Path(tempfile.mkdtemp(prefix=f".{output_tree.name}.signing.", dir=output_tree.parent))
    staging_root.chmod(0o700)
    staging_identity = staging_root.stat()
    signed_tree = staging_root / "payload"
    try:
        shutil.copytree(unsigned_tree, signed_tree, symlinks=True)
        _verify_unsigned_manifest(signed_tree)
        binary, source = _rpm_closure(signed_tree)
        if (
            _sha256(signed_tree / "SHA256SUMS") != unsigned_manifest_sha256
            or [
                {"kind": "binary", "sha256": _sha256(binary)},
                {"kind": "source", "sha256": _sha256(source)},
            ]
            != unsigned_rpm_sha256
        ):
            raise SigningError
        for rpm_path in (binary, source):
            queried = _run(
                (
                    tool_paths["rpm"],
                    "-qp",
                    "--qf",
                    "%{NAME}\\n",
                    os.fspath(rpm_path),
                ),
                env=base_env,
                run_command=run_command,
            )
            if queried != f"{package_name}\n".encode("ascii"):
                raise SigningError
            with _staged_rpm_write_access(rpm_path):
                _run(
                    (
                        tool_paths["rpmsign"],
                        "--define",
                        f"_gpg_name {signing_subkey_fingerprint}!",
                        "--define",
                        f"_gpg_path {gnupg_home}",
                        "--define",
                        "__gpg /usr/bin/gpg",
                        "--addsign",
                        os.fspath(rpm_path),
                    ),
                    env=signing_env,
                    run_command=run_command,
                )

        verification_home = staging_root / "verification-gnupg"
        rpmdb = staging_root / "rpmdb"
        verification_home.mkdir(mode=0o700)
        rpmdb.mkdir(mode=0o700)
        verify_env = {**base_env, "GNUPGHOME": os.fspath(verification_home)}
        _run(
            (tool_paths["gpg"], "--homedir", os.fspath(verification_home), "--batch", "--import", os.fspath(public_key)),
            env=verify_env,
            run_command=run_command,
        )
        _run(
            (
                tool_paths["rpmkeys"],
                "--dbpath",
                os.fspath(rpmdb),
                "--import",
                os.fspath(public_key),
            ),
            env=base_env,
            run_command=run_command,
        )
        for rpm_path in (binary, source):
            signature_check = _run(
                (tool_paths["rpmkeys"], "--dbpath", os.fspath(rpmdb), "--checksig", "--verbose", os.fspath(rpm_path)),
                env=base_env,
                run_command=run_command,
            )
            normalized_check = signature_check.lower()
            if (
                b"signature" not in normalized_check
                or b"rsa/sha256 signature" not in normalized_check
                or signing_subkey_fingerprint[-8:].lower().encode("ascii")
                not in normalized_check
                or b"not ok" in normalized_check
            ):
                raise SigningError

        report: dict[str, Any] = {
            "package_name": package_name,
            "policy_sha256": _sha256(policy_file),
            "primary_fingerprint": primary_fingerprint,
            "public_key_sha256": policy["public_key_sha256"],
            "rpm_sha256": sorted((_sha256(binary), _sha256(source))),
            "schema_version": 1,
            "signing_subkey_fingerprint": signing_subkey_fingerprint,
            "status": "signed",
            "unsigned_manifest_sha256": unsigned_manifest_sha256,
            "unsigned_rpm_sha256": unsigned_rpm_sha256,
        }
        (signed_tree / "SHA256SUMS").unlink()
        _atomic_write(
            signed_tree / "SIGNING.json",
            (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
        )
        _atomic_write(
            signed_tree / "SHA256SUMS",
            "".join(_manifest_rows(signed_tree, exclude_signature=True)).encode("ascii"),
        )
        signature = signed_tree / "SHA256SUMS.asc"
        _run(
            (
                tool_paths["gpg"],
                "--homedir",
                os.fspath(gnupg_home),
                "--batch",
                "--armor",
                "--local-user",
                f"{signing_subkey_fingerprint}!",
                "--output",
                os.fspath(signature),
                "--detach-sign",
                os.fspath(signed_tree / "SHA256SUMS"),
            ),
            env=signing_env,
            run_command=run_command,
        )
        if not signature.is_file() or signature.is_symlink():
            raise SigningError
        signature.chmod(0o644)
        status_output = _run(
            (
                tool_paths["gpg"],
                "--homedir",
                os.fspath(verification_home),
                "--batch",
                "--status-fd=1",
                "--verify",
                os.fspath(signature),
                os.fspath(signed_tree / "SHA256SUMS"),
            ),
            env=verify_env,
            run_command=run_command,
        )
        try:
            valid_signatures = [
                line.decode("ascii").split()
                for line in status_output.splitlines()
                if line.startswith(b"[GNUPG:] VALIDSIG ")
            ]
        except UnicodeError as error:
            raise SigningError from error
        if (
            len(valid_signatures) != 1
            or len(valid_signatures[0]) != 12
            or valid_signatures[0][2] != signing_subkey_fingerprint
            or valid_signatures[0][9] != "8"
            or valid_signatures[0][11] != primary_fingerprint
        ):
            raise SigningError
        if (signed_tree / "SHA256SUMS").read_text(encoding="ascii") != "".join(
            _manifest_rows(signed_tree, exclude_signature=True)
        ):
            raise SigningError
        directory_fd = os.open(
            output_tree.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        staging_fd = os.open(
            staging_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            parent_status = os.fstat(directory_fd)
            staging_status = os.fstat(staging_fd)
            if (
                (parent_status.st_dev, parent_status.st_ino)
                != (output_parent_identity.st_dev, output_parent_identity.st_ino)
                or (staging_status.st_dev, staging_status.st_ino)
                != (staging_identity.st_dev, staging_identity.st_ino)
            ):
                raise SigningError
            _rename_noreplace(
                staging_fd,
                "payload",
                directory_fd,
                output_tree.name,
            )
            os.fsync(directory_fd)
        finally:
            os.close(staging_fd)
            os.close(directory_fd)
        return report
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(error, SigningError):
            raise
        raise SigningError from error
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--unsigned-tree", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--package-name", required=True)
    parser.add_argument("--gnupg-home", required=True, type=Path)
    parser.add_argument("--primary-fingerprint", required=True)
    parser.add_argument("--signing-subkey-fingerprint", required=True)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    try:
        args = parser.parse_args(argv)
        report = sign_tree(
            args.unsigned_tree,
            args.output,
            package_name=args.package_name,
            gnupg_home=args.gnupg_home,
            primary_fingerprint=args.primary_fingerprint,
            signing_subkey_fingerprint=args.signing_subkey_fingerprint,
            policy_file=args.policy,
            public_key=args.public_key,
        )
        sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except (OSError, SigningError, TypeError, ValueError):
        with contextlib.suppress(OSError):
            sys.stderr.write("RPM release signing failed\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
