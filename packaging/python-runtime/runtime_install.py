"""Install the sealed wheel closure into the private LTO Archiver runtime."""

from __future__ import annotations

import argparse
import base64
import binascii
import compileall
import csv
import hashlib
import importlib.util
import io
import json
import marshal
import os
import py_compile
import re
import shutil
import stat
import struct
import sys
import tarfile
import tempfile
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path, PurePosixPath
from types import CodeType, ModuleType
from typing import Any
from zipfile import BadZipFile, ZipFile

PRIVATE_RUNTIME_ROOT = "/usr/lib64/lto-archiver/python-runtime/3.11/site-packages"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
NORMALIZE_PATTERN = re.compile(r"[-_.]+")
PAYLOAD_AUTHORITY_KEYS = {
    "file_count",
    "filelist_sha256",
    "installed_root",
    "native_extension_paths",
    "pyc_count",
    "python_cache_tag",
    "schema_version",
    "wheel_count",
}


class RuntimeInstallError(ValueError):
    """The private runtime cannot be authenticated or installed safely."""


def _normalize_name(value: str) -> str:
    return NORMALIZE_PATTERN.sub("-", value).lower()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        with path.open("rb") as source:
            return hashlib.file_digest(source, "sha256").hexdigest()
    except OSError as error:
        raise RuntimeInstallError(f"cannot hash {path}: {error}") from error


def _unsafe_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        not name
        or "\\" in name
        or name != path.as_posix()
        or bool(path.parts and re.fullmatch(r"[A-Za-z]:", path.parts[0]))
        or any(
            ord(character) < 32 or 127 <= ord(character) <= 159 for character in name
        )
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    )


def _member_kind(member: Any) -> int:
    return stat.S_IFMT(member.external_attr >> 16)


def _validated_members(wheel: Path, archive: ZipFile) -> list[Any]:
    members = archive.infolist()
    exact: set[str] = set()
    folded: dict[str, str] = {}
    for member in members:
        name = member.orig_filename
        if _unsafe_name(name.rstrip("/")):
            raise RuntimeInstallError(f"{wheel.name}: unsafe wheel member {name!r}")
        if name in exact:
            raise RuntimeInstallError(f"{wheel.name}: duplicate wheel member {name!r}")
        exact.add(name)
        folded_name = name.casefold()
        if folded_name in folded:
            raise RuntimeInstallError(
                f"{wheel.name}: casefold collision {folded[folded_name]!r} / {name!r}"
            )
        folded[folded_name] = name
        kind = _member_kind(member)
        if kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
            raise RuntimeInstallError(
                f"{wheel.name}: unsafe special wheel member {name!r}"
            )
        if (kind == stat.S_IFDIR and not name.endswith("/")) or (
            kind == stat.S_IFREG and name.endswith("/")
        ):
            raise RuntimeInstallError(
                f"{wheel.name}: unsafe wheel member type {name!r}"
            )
        if member.flag_bits & 1:
            raise RuntimeInstallError(f"{wheel.name}: encrypted wheel member {name!r}")
    return members


def _single_member(names: list[str], suffix: str, wheel: Path) -> str:
    matches = [name for name in names if name.endswith(suffix)]
    if len(matches) != 1:
        raise RuntimeInstallError(f"{wheel.name}: expected exactly one {suffix} member")
    return matches[0]


def _filename_tags(
    filename: str,
) -> tuple[str, str, list[str], list[str], list[str], set[str]]:
    if not filename.endswith(".whl"):
        raise RuntimeInstallError(f"not a wheel filename: {filename}")
    parts = filename[:-4].split("-")
    if len(parts) != 5:
        raise RuntimeInstallError(f"malformed wheel filename: {filename}")
    distribution, version, python_field, abi_field, platform_field = parts
    python_tags = python_field.split(".")
    abi_tags = abi_field.split(".")
    platform_tags = platform_field.split(".")
    expanded = {
        f"{python_tag}-{abi_tag}-{platform_tag}"
        for python_tag in python_tags
        for abi_tag in abi_tags
        for platform_tag in platform_tags
    }
    return distribution, version, python_tags, abi_tags, platform_tags, expanded


def _validate_tags(
    wheel: Path,
    component: dict[str, Any],
    wheel_metadata: Any,
) -> None:
    (
        distribution,
        filename_version,
        python_tags,
        abi_tags,
        platform_tags,
        expanded,
    ) = _filename_tags(wheel.name)
    declared_tags = wheel_metadata.get_all("Tag") or []
    root_value = wheel_metadata.get("Root-Is-Purelib")
    if (
        _normalize_name(distribution) != component.get("normalized_name")
        or filename_version != component.get("version")
        or python_tags != component.get("python_tags")
        or abi_tags != component.get("abi_tags")
        or platform_tags != component.get("platform_tags")
        or expanded != set(component.get("wheel_tags", []))
        or declared_tags != component.get("wheel_tags")
        or root_value != str(component.get("root_is_purelib")).lower()
    ):
        raise RuntimeInstallError(f"{wheel.name}: wheel tag or identity mismatch")
    if component.get("root_is_purelib"):
        if component.get("architecture") != "noarch" or platform_tags != ["any"]:
            raise RuntimeInstallError(f"{wheel.name}: pure wheel tag mismatch")
    else:
        compatible = any(
            python_tag == "cp311" or (python_tag == "cp310" and abi_tag == "abi3")
            for python_tag in python_tags
            for abi_tag in abi_tags
        )
        if (
            component.get("architecture") != "x86_64"
            or not all(tag.endswith("_x86_64") for tag in platform_tags)
            or not compatible
        ):
            raise RuntimeInstallError(f"{wheel.name}: native wheel tag mismatch")


def _decode_record(wheel: Path, payload: bytes) -> list[tuple[str, str, str]]:
    try:
        text = payload.decode("utf-8")
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (UnicodeError, csv.Error) as error:
        raise RuntimeInstallError(f"{wheel.name}: malformed RECORD") from error
    if not rows or any(len(row) != 3 for row in rows):
        raise RuntimeInstallError(f"{wheel.name}: malformed RECORD")
    result: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    folded: dict[str, str] = {}
    for path, digest, size in rows:
        if _unsafe_name(path) or path in seen:
            raise RuntimeInstallError(f"{wheel.name}: malformed RECORD path")
        folded_path = path.casefold()
        if folded_path in folded:
            raise RuntimeInstallError(f"{wheel.name}: RECORD casefold collision")
        seen.add(path)
        folded[folded_path] = path
        result.append((path, digest, size))
    return result


def _validate_record(
    wheel: Path,
    record_name: str,
    rows: list[tuple[str, str, str]],
    payloads: dict[str, bytes],
) -> None:
    by_path = {path: (digest, size) for path, digest, size in rows}
    if set(by_path) != set(payloads):
        raise RuntimeInstallError(f"{wheel.name}: RECORD file closure mismatch")
    for path, payload in payloads.items():
        digest, size = by_path[path]
        if path == record_name:
            if digest or size:
                raise RuntimeInstallError(
                    f"{wheel.name}: RECORD self-entry must be unhashed"
                )
            continue
        if not size.isascii() or not size.isdecimal() or int(size) != len(payload):
            raise RuntimeInstallError(f"{wheel.name}: RECORD size mismatch for {path}")
        if not digest.startswith("sha256="):
            raise RuntimeInstallError(f"{wheel.name}: RECORD hash mismatch for {path}")
        encoded = digest.removeprefix("sha256=")
        try:
            if not encoded or "=" in encoded:
                raise ValueError
            decoded = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
            )
        except (binascii.Error, ValueError, UnicodeError) as error:
            raise RuntimeInstallError(
                f"{wheel.name}: malformed RECORD hash for {path}"
            ) from error
        if decoded != hashlib.sha256(payload).digest():
            raise RuntimeInstallError(f"{wheel.name}: RECORD hash mismatch for {path}")


def _destination_for_member(
    wheel: Path,
    member_name: str,
    dist_info: str,
) -> PurePosixPath:
    member = PurePosixPath(member_name)
    data_parts = [
        index for index, part in enumerate(member.parts) if part.endswith(".data")
    ]
    if not data_parts:
        return member
    expected_data = dist_info.removesuffix(".dist-info") + ".data"
    if (
        data_parts != [0]
        or member.parts[0] != expected_data
        or len(member.parts) < 3
        or member.parts[1] not in {"purelib", "platlib"}
    ):
        raise RuntimeInstallError(
            f"{wheel.name}: unexpected wheel data layout {member_name!r}"
        )
    return PurePosixPath(*member.parts[2:])


def validate_wheel(wheel: Path, component: dict[str, Any]) -> dict[str, bytes]:
    """Validate one wheel completely and return its private-root file mapping."""

    if wheel.name != component.get("filename"):
        raise RuntimeInstallError(f"{wheel.name}: wheel filename mismatch")
    expected_digest = component.get("sha256")
    if expected_digest is not None and _sha256_file(wheel) != expected_digest:
        raise RuntimeInstallError(f"{wheel.name}: wheel SHA-256 mismatch")
    try:
        with ZipFile(wheel) as archive:
            members = _validated_members(wheel, archive)
            names = [member.orig_filename for member in members if not member.is_dir()]
            metadata_name = _single_member(names, ".dist-info/METADATA", wheel)
            wheel_metadata_name = _single_member(names, ".dist-info/WHEEL", wheel)
            record_name = _single_member(names, ".dist-info/RECORD", wheel)
            dist_info = metadata_name.removesuffix("/METADATA")
            if (
                wheel_metadata_name != f"{dist_info}/WHEEL"
                or record_name != f"{dist_info}/RECORD"
            ):
                raise RuntimeInstallError(f"{wheel.name}: split dist-info metadata")
            payloads = {name: archive.read(name) for name in names}
    except (BadZipFile, KeyError, OSError, RuntimeError) as error:
        if isinstance(error, RuntimeInstallError):
            raise
        raise RuntimeInstallError(f"{wheel.name}: cannot read wheel") from error

    metadata = BytesParser(policy=compat32).parsebytes(payloads[metadata_name])
    wheel_metadata = BytesParser(policy=compat32).parsebytes(
        payloads[wheel_metadata_name]
    )
    if (
        metadata.get("Name") != component.get("name")
        or metadata.get("Version") != component.get("version")
        or _normalize_name(metadata.get("Name", "")) != component.get("normalized_name")
    ):
        raise RuntimeInstallError(f"{wheel.name}: wheel metadata identity mismatch")
    _validate_tags(wheel, component, wheel_metadata)
    rows = _decode_record(wheel, payloads[record_name])
    _validate_record(wheel, record_name, rows, payloads)

    destinations: dict[str, bytes] = {}
    folded: dict[str, str] = {}
    for member_name, payload in payloads.items():
        if (
            member_name.endswith((".pyc", ".pyo"))
            or "__pycache__" in PurePosixPath(member_name).parts
        ):
            raise RuntimeInstallError(
                f"{wheel.name}: precompiled bytecode is forbidden"
            )
        destination = _destination_for_member(wheel, member_name, dist_info)
        name = destination.as_posix()
        folded_name = name.casefold()
        if name in destinations or folded_name in folded:
            raise RuntimeInstallError(f"{wheel.name}: destination collision for {name}")
        destinations[name] = payload
        folded[folded_name] = name
    return destinations


def _load_source_tool(path: Path) -> ModuleType:
    if not path.is_file() or path.is_symlink():
        raise RuntimeInstallError("trusted runtime source tool is not a regular file")
    try:
        source = path.read_bytes()
        code = compile(source, str(path), "exec", dont_inherit=True)
        module = ModuleType("_lto_runtime_source_verifier")
        module.__file__ = str(path)
        exec(code, module.__dict__)  # noqa: S102 - execute the authenticated verifier.
    except (ImportError, OSError, SyntaxError, ValueError) as error:
        raise RuntimeInstallError("cannot load runtime source verifier") from error
    return module


def _authenticate_source(source: Path, authority_root: Path) -> dict[str, Any]:
    verifier = _load_source_tool(authority_root / "runtime_source.py")
    try:
        verifier.verify_source(source, authority_root)
        inventory = verifier.load_json(authority_root / "wheel-inventory.json")
    except Exception as error:
        runtime_source_error = getattr(verifier, "RuntimeSourceError", ())
        if runtime_source_error and isinstance(error, runtime_source_error):
            raise RuntimeInstallError(str(error)) from error
        raise
    if not isinstance(inventory, dict):
        raise RuntimeInstallError("trusted wheel inventory is malformed")
    return inventory


def _validate_output(output: Path) -> None:
    if not output.is_absolute() or output.name in {"", ".", ".."}:
        raise RuntimeInstallError("output must be an absolute new directory")
    if output.exists() or output.is_symlink():
        raise RuntimeInstallError("output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        if output.parent.resolve(strict=True) != output.parent:
            raise RuntimeInstallError("output parent contains a symlink")
    except OSError as error:
        raise RuntimeInstallError("cannot resolve output parent") from error


def _merge_wheels(source: Path, inventory: dict[str, Any]) -> dict[str, bytes]:
    merged: dict[str, bytes] = {}
    folded_files: dict[str, str] = {}
    directory_names: dict[str, str] = {}
    for component in inventory["wheels"]:
        files = validate_wheel(source / "wheels" / component["filename"], component)
        for name, payload in files.items():
            folded = name.casefold()
            if folded in folded_files or folded in directory_names:
                raise RuntimeInstallError(f"runtime destination collision for {name}")
            parent = PurePosixPath(name).parent
            while parent != PurePosixPath("."):
                parent_name = parent.as_posix()
                parent_folded = parent_name.casefold()
                if parent_folded in folded_files:
                    raise RuntimeInstallError(
                        f"runtime file/directory collision for {name}"
                    )
                existing_directory = directory_names.get(parent_folded)
                if existing_directory is not None and existing_directory != parent_name:
                    raise RuntimeInstallError(
                        "runtime casefold directory collision for "
                        f"{existing_directory} / {parent_name}"
                    )
                directory_names[parent_folded] = parent_name
                parent = parent.parent
            merged[name] = payload
            folded_files[folded] = name
    return merged


def _all_code_filenames(code: CodeType) -> set[str]:
    result = {code.co_filename}
    for constant in code.co_consts:
        if isinstance(constant, CodeType):
            result.update(_all_code_filenames(constant))
    return result


def _verify_bytecode(staging: Path, installed_root: str) -> None:
    python_sources = sorted(staging.rglob("*.py"))
    for source in python_sources:
        bytecode = Path(importlib.util.cache_from_source(str(source)))
        if not bytecode.is_file():
            raise RuntimeInstallError(f"missing bytecode for {source.name}")
        payload = bytecode.read_bytes()
        if len(payload) < 16 or payload[:4] != importlib.util.MAGIC_NUMBER:
            raise RuntimeInstallError(f"invalid bytecode header for {source.name}")
        if struct.unpack("<I", payload[4:8])[0] != 3:
            raise RuntimeInstallError(f"bytecode is not checked-hash for {source.name}")
        try:
            code = marshal.loads(payload[16:])
        except (EOFError, TypeError, ValueError) as error:
            raise RuntimeInstallError(f"invalid bytecode for {source.name}") from error
        expected = f"{installed_root}/{source.relative_to(staging).as_posix()}"
        if _all_code_filenames(code) != {expected}:
            raise RuntimeInstallError(
                f"bytecode filename is not normalized for {source.name}"
            )


def _write_payload(
    staging: Path,
    files: dict[str, bytes],
    installed_root: str,
    source_date_epoch: int,
) -> None:
    for relative, payload in sorted(files.items()):
        destination = staging.joinpath(*PurePosixPath(relative).parts)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        destination.write_bytes(payload)
        destination.chmod(0o644)
    compiled = compileall.compile_dir(
        staging,
        force=True,
        quiet=2,
        legacy=False,
        optimize=0,
        stripdir=str(staging),
        prependdir=installed_root,
        invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH,
    )
    if not compiled:
        raise RuntimeInstallError("checked-hash bytecode compilation failed")
    _verify_bytecode(staging, installed_root)
    paths = sorted(staging.rglob("*"), key=lambda path: len(path.parts), reverse=True)
    for path in paths:
        if path.is_symlink():
            raise RuntimeInstallError("runtime staging contains a symlink")
        if path.is_file():
            path.chmod(0o644)
        elif path.is_dir():
            path.chmod(0o755)
        else:
            raise RuntimeInstallError("runtime staging contains a special file")
        os.utime(path, (source_date_epoch, source_date_epoch), follow_symlinks=False)
    staging.chmod(0o755)
    os.utime(staging, (source_date_epoch, source_date_epoch), follow_symlinks=False)


def _validate_payload_authority(
    staging: Path,
    authority_path: Path,
    installed_root: str,
    expected_python: str,
    wheel_count: int,
) -> None:
    try:
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeInstallError("cannot read payload filelist authority") from error
    if not isinstance(authority, dict) or set(authority) != PAYLOAD_AUTHORITY_KEYS:
        raise RuntimeInstallError("malformed payload filelist authority")
    expected_tag = "cpython-" + expected_python.replace(".", "")
    if (
        authority.get("schema_version") != 1
        or authority.get("installed_root") != installed_root
        or authority.get("python_cache_tag") != expected_tag
        or authority.get("wheel_count") != wheel_count
        or not SHA256_PATTERN.fullmatch(str(authority.get("filelist_sha256", "")))
        or not isinstance(authority.get("native_extension_paths"), list)
    ):
        raise RuntimeInstallError("payload filelist authority target mismatch")
    paths = sorted(
        path.relative_to(staging).as_posix()
        for path in staging.rglob("*")
        if path.is_file()
    )
    filelist = "".join(f"{path}\n" for path in paths).encode("utf-8")
    native = sorted(path for path in paths if path.endswith(".so"))
    pyc_count = sum(path.endswith(".pyc") for path in paths)
    if (
        len(paths) != authority.get("file_count")
        or pyc_count != authority.get("pyc_count")
        or native != authority.get("native_extension_paths")
        or _sha256_bytes(filelist) != authority.get("filelist_sha256")
    ):
        raise RuntimeInstallError("payload filelist does not match authority")


def install_runtime(
    source: Path,
    authority_root: Path,
    output: Path,
    installed_root: str,
    source_date_epoch: int,
    expected_python: str,
    expected_wheel_count: int | None = None,
    payload_authority: Path | None = None,
) -> None:
    """Authenticate, validate, compile, and atomically publish a runtime tree."""

    actual_python = f"{sys.version_info.major}.{sys.version_info.minor}"
    if expected_python != actual_python:
        raise RuntimeInstallError(
            f"runtime installer requires Python {expected_python}, got {actual_python}"
        )
    if installed_root != PRIVATE_RUNTIME_ROOT:
        raise RuntimeInstallError("runtime installed root is not the private target")
    _validate_output(output)
    inventory = _authenticate_source(source, authority_root)
    runtime = inventory.get("runtime", {})
    wheels = inventory.get("wheels")
    if (
        runtime.get("python_version") != "3.11"
        or runtime.get("architecture") != "x86_64"
        or runtime.get("source_date_epoch") != source_date_epoch
        or not isinstance(wheels, list)
    ):
        raise RuntimeInstallError("runtime target, epoch, or inventory mismatch")
    if expected_wheel_count is not None and len(wheels) != expected_wheel_count:
        raise RuntimeInstallError("runtime wheel count mismatch")
    files = _merge_wheels(source, inventory)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.staging.", dir=output.parent)
    )
    try:
        _write_payload(staging, files, installed_root, source_date_epoch)
        if payload_authority is not None:
            _validate_payload_authority(
                staging,
                payload_authority,
                installed_root,
                expected_python,
                len(wheels),
            )
        staging.rename(output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _parse_digest_file(path: Path, expected_filename: str) -> str:
    try:
        fields = path.read_text(encoding="ascii").strip().split()
    except (OSError, UnicodeError) as error:
        raise RuntimeInstallError("cannot read Source0 digest") from error
    if (
        len(fields) != 2
        or not SHA256_PATTERN.fullmatch(fields[0])
        or fields[1].lstrip("*") != expected_filename
    ):
        raise RuntimeInstallError("malformed Source0 digest authority")
    return fields[0]


def _extract_authenticated_source0(
    archive_path: Path,
    digest_path: Path,
    destination: Path,
    source_date_epoch: int,
) -> Path:
    expected_digest = _parse_digest_file(digest_path, archive_path.name)
    if _sha256_file(archive_path) != expected_digest:
        raise RuntimeInstallError("Source0 SHA-256 mismatch")
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if names != sorted(names) or len(names) != len(set(names)):
                raise RuntimeInstallError("noncanonical Source0 member order")
            folded: set[str] = set()
            prefixes: set[str] = set()
            for member in members:
                name = member.name.rstrip("/")
                if _unsafe_name(name):
                    raise RuntimeInstallError(f"unsafe Source0 member {member.name!r}")
                if name.casefold() in folded:
                    raise RuntimeInstallError("Source0 casefold collision")
                folded.add(name.casefold())
                prefixes.add(PurePosixPath(name).parts[0])
                expected_mode = 0o755 if member.isdir() else 0o644
                if (
                    not (member.isdir() or member.isfile())
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mtime != source_date_epoch
                    or member.mode != expected_mode
                ):
                    raise RuntimeInstallError("noncanonical Source0 header")
            if len(prefixes) != 1:
                raise RuntimeInstallError("Source0 must have one top-level directory")
            for member in members:
                target = destination.joinpath(*PurePosixPath(member.name).parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=False)
                    target.chmod(0o755)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise RuntimeInstallError("cannot read Source0 member")
                    target.write_bytes(extracted.read())
                    target.chmod(0o644)
    except (OSError, tarfile.TarError) as error:
        raise RuntimeInstallError("cannot read Source0") from error
    return destination / next(iter(prefixes))


def install_source0(
    archive: Path,
    digest: Path,
    output: Path,
    installed_root: str,
    source_date_epoch: int,
    expected_python: str,
    expected_wheel_count: int,
    payload_authority: Path | None = None,
) -> None:
    """Install directly from the digest-bound canonical Source0 archive."""

    with tempfile.TemporaryDirectory(prefix="lto-runtime-source0.") as temporary:
        source = _extract_authenticated_source0(
            archive, digest, Path(temporary), source_date_epoch
        )
        verifier = _load_source_tool(source / "tools" / "runtime_source.py")
        inventory = verifier.load_json(source / "wheel-inventory.json")
        try:
            verifier._verify_source_against_trusted(
                source, inventory, source / "tools" / "runtime_source.py"
            )
        except Exception as error:
            runtime_source_error = getattr(verifier, "RuntimeSourceError", ())
            if runtime_source_error and isinstance(error, runtime_source_error):
                raise RuntimeInstallError(str(error)) from error
            raise
        # The archive digest is the independent authority in this mode. Reuse the
        # authenticated verifier's inventory without copying binary wheel input.
        files = _merge_wheels(source, inventory)
        actual_python = f"{sys.version_info.major}.{sys.version_info.minor}"
        if expected_python != actual_python:
            raise RuntimeInstallError(
                f"runtime installer requires Python {expected_python}, got {actual_python}"
            )
        if installed_root != PRIVATE_RUNTIME_ROOT:
            raise RuntimeInstallError(
                "runtime installed root is not the private target"
            )
        if inventory["runtime"].get("source_date_epoch") != source_date_epoch:
            raise RuntimeInstallError("runtime SOURCE_DATE_EPOCH mismatch")
        if len(inventory.get("wheels", [])) != expected_wheel_count:
            raise RuntimeInstallError("runtime wheel count mismatch")
        _validate_output(output)
        staging = Path(
            tempfile.mkdtemp(prefix=f".{output.name}.staging.", dir=output.parent)
        )
        try:
            _write_payload(staging, files, installed_root, source_date_epoch)
            if payload_authority is not None:
                _validate_payload_authority(
                    staging,
                    payload_authority,
                    installed_root,
                    expected_python,
                    len(inventory["wheels"]),
                )
            staging.rename(output)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--installed-root", required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--expected-python", default="3.11")
    parser.add_argument("--expected-wheel-count", type=int)
    parser.add_argument("--payload-authority", type=Path)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("install", help="install a trusted sealed tree")
    install.add_argument("--source", type=Path, required=True)
    install.add_argument("--authority-root", type=Path, required=True)
    _common_arguments(install)
    source0 = commands.add_parser(
        "install-source0", help="install a digest-bound canonical Source0"
    )
    source0.add_argument("--archive", type=Path, required=True)
    source0.add_argument("--expected-sha256", type=Path, required=True)
    _common_arguments(source0)
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _argument_parser().parse_args(arguments)
    try:
        if options.command == "install":
            install_runtime(
                options.source,
                options.authority_root,
                options.output,
                options.installed_root,
                options.source_date_epoch,
                options.expected_python,
                options.expected_wheel_count,
                options.payload_authority,
            )
        elif options.command == "install-source0":
            if options.expected_wheel_count is None:
                raise RuntimeInstallError("Source0 installation requires a wheel count")
            install_source0(
                options.archive,
                options.expected_sha256,
                options.output,
                options.installed_root,
                options.source_date_epoch,
                options.expected_python,
                options.expected_wheel_count,
                options.payload_authority,
            )
        else:  # pragma: no cover - argparse enforces the command.
            raise RuntimeInstallError("unsupported command")
    except RuntimeInstallError as error:
        print(f"runtime install error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
