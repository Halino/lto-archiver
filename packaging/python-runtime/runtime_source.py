"""Seal and verify the offline Python runtime source using the standard library."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from datetime import UTC, datetime
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path, PurePosixPath
from typing import Any
from zipfile import BadZipFile, ZipFile

SCHEMA_VERSION = 1
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
NORMALIZE_PATTERN = re.compile(r"[-_.]+")
INVENTORY_KEYS = {"schema_version", "runtime", "wheels"}
RUNTIME_KEYS = {
    "aggregate_license",
    "architecture",
    "authorized_lock_sha256",
    "name",
    "python_version",
    "source_date_epoch",
    "version",
    "wheel_count",
}
WHEEL_KEYS = {
    "abi_tags",
    "architecture",
    "dependencies",
    "filename",
    "license_expression",
    "license_files",
    "metadata_requires_dist",
    "name",
    "normalized_name",
    "platform_tags",
    "python_tags",
    "root_is_purelib",
    "sha256",
    "version",
    "wheel_tags",
}
LICENSE_FILE_KEYS = {"path", "sha256", "wheel_member"}
RUNTIME_LICENSE = "BSD-3-Clause AND MIT AND MIT-0 AND MPL-2.0 AND PSF-2.0"
COMPONENT_LICENSES = {"BSD-3-Clause", "MIT", "MIT-0", "MPL-2.0", "PSF-2.0"}
EXCLUDED_RUNTIME_PROJECTS = {"packaging", "setuptools", "wheel"}


class RuntimeSourceError(ValueError):
    """The runtime source does not match its closed authority."""


def normalize_name(value: str) -> str:
    return NORMALIZE_PATTERN.sub("-", value).lower()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeSourceError(f"cannot read JSON {path}: {error}") from error


def parse_hash_lock(path: Path) -> dict[tuple[str, str], set[str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise RuntimeSourceError(f"cannot read hash lock {path}: {error}") from error
    result: dict[tuple[str, str], set[str]] = {}
    current: tuple[str, str] | None = None
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not raw_line[:1].isspace():
            requirement = line.removesuffix("\\").strip().split(";", 1)[0].strip()
            requirement = requirement.split(" ", 1)[0]
            if "==" not in requirement:
                raise RuntimeSourceError(f"unsupported lock requirement: {line}")
            name, version = requirement.split("==", 1)
            current = (normalize_name(name), version)
            if current in result:
                raise RuntimeSourceError(
                    f"duplicate lock requirement: {current[0]}=={current[1]}"
                )
            result[current] = set()
        if current is None:
            raise RuntimeSourceError(f"hash without requirement: {line}")
        for digest in re.findall(r"--hash=sha256:([0-9a-fA-F]{64})", line):
            result[current].add(digest.lower())
    for requirement, hashes in result.items():
        if not hashes:
            raise RuntimeSourceError(
                f"lock requirement has no SHA-256: {requirement[0]}=={requirement[1]}"
            )
    return result


def parse_digest_file(path: Path, expected_filename: str) -> str:
    try:
        line = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as error:
        raise RuntimeSourceError(
            f"cannot read SHA-256 authority {path}: {error}"
        ) from error
    fields = line.split()
    if len(fields) != 2 or not SHA256_PATTERN.fullmatch(fields[0]):
        raise RuntimeSourceError(f"malformed SHA-256 authority: {path}")
    if fields[1].lstrip("*") != expected_filename:
        raise RuntimeSourceError(f"SHA-256 authority filename mismatch: {path}")
    return fields[0]


def _single_member(names: list[str], suffix: str, wheel_name: str) -> str:
    matches = [name for name in names if name.endswith(suffix)]
    if len(matches) != 1:
        raise RuntimeSourceError(
            f"{wheel_name}: expected one {suffix} member, found {len(matches)}"
        )
    return matches[0]


def _validated_zip_members(path: Path, archive: ZipFile) -> list[Any]:
    members = archive.infolist()
    exact: set[str] = set()
    folded: dict[str, str] = {}
    for member in members:
        name = member.orig_filename
        unsafe = (
            not name
            or "\\" in name
            or any(
                ord(character) < 32 or 127 <= ord(character) <= 159
                for character in name
            )
            or PurePosixPath(name).is_absolute()
            or ".." in PurePosixPath(name).parts
        )
        if unsafe:
            raise RuntimeSourceError(f"{path.name}: unsafe wheel member {name!r}")
        if name in exact:
            raise RuntimeSourceError(
                f"{path.name}: unsafe wheel member duplicate {name!r}"
            )
        exact.add(name)
        folded_name = name.casefold()
        if folded_name in folded:
            raise RuntimeSourceError(
                f"{path.name}: unsafe wheel member casefold collision "
                f"{folded[folded_name]!r} / {name!r}"
            )
        folded[folded_name] = name
        unix_mode = member.external_attr >> 16
        file_type = stat.S_IFMT(unix_mode)
        if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
            raise RuntimeSourceError(
                f"{path.name}: unsafe wheel member special type {name!r}"
            )
        if (file_type == stat.S_IFDIR and not name.endswith("/")) or (
            file_type == stat.S_IFREG and name.endswith("/")
        ):
            raise RuntimeSourceError(
                f"{path.name}: unsafe wheel member directory attributes {name!r}"
            )
    return members


def inspect_wheel(path: Path) -> dict[str, Any]:
    try:
        with ZipFile(path) as archive:
            members = _validated_zip_members(path, archive)
            names = [member.orig_filename for member in members]
            metadata_member = _single_member(names, ".dist-info/METADATA", path.name)
            wheel_member = _single_member(names, ".dist-info/WHEEL", path.name)
            metadata = BytesParser(policy=compat32).parsebytes(
                archive.read(metadata_member)
            )
            wheel_metadata = BytesParser(policy=compat32).parsebytes(
                archive.read(wheel_member)
            )
            license_contents = {
                member.orig_filename: archive.read(member)
                for member in members
                if not member.is_dir()
            }
    except (BadZipFile, KeyError, OSError) as error:
        raise RuntimeSourceError(
            f"cannot inspect wheel {path.name}: {error}"
        ) from error
    name = metadata.get("Name")
    version = metadata.get("Version")
    root_value = wheel_metadata.get("Root-Is-Purelib")
    tags = wheel_metadata.get_all("Tag") or []
    if not name or not version or root_value not in {"true", "false"} or not tags:
        raise RuntimeSourceError(f"{path.name}: incomplete METADATA or WHEEL identity")
    license_expression = metadata.get("License-Expression")
    if not license_expression and metadata.get("License") in {
        "BSD-3-Clause",
        "MIT",
        "MIT-0",
        "MPL-2.0",
        "PSF-2.0",
    }:
        license_expression = metadata.get("License")
    if not license_expression:
        classifiers = metadata.get_all("Classifier") or []
        classifier_licenses = {
            "License :: OSI Approved :: BSD License": "BSD-3-Clause",
            "License :: OSI Approved :: MIT License": "MIT",
            "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": (
                "MPL-2.0"
            ),
        }
        matches = {
            classifier_licenses[classifier]
            for classifier in classifiers
            if classifier in classifier_licenses
        }
        if len(matches) == 1:
            license_expression = matches.pop()
    license_members = sorted(
        member
        for member in names
        if not member.endswith("/")
        and ".dist-info/" in member
        and PurePosixPath(member)
        .name.lower()
        .startswith(("license", "licence", "copying", "notice"))
    )
    return {
        "name": name,
        "normalized_name": normalize_name(name),
        "version": version,
        "root_is_purelib": root_value == "true",
        "wheel_tags": tags,
        "license_expression": license_expression,
        "license_members": license_members,
        "metadata_requires_dist": metadata.get_all("Requires-Dist") or [],
        "members": license_contents,
    }


def filename_tags(
    filename: str,
) -> tuple[str, str, list[str], list[str], list[str], set[str]]:
    if not filename.endswith(".whl"):
        raise RuntimeSourceError(f"not a wheel filename: {filename}")
    parts = filename[:-4].split("-")
    if len(parts) != 5:
        raise RuntimeSourceError(f"malformed wheel filename: {filename}")
    distribution, version, python_tag_field, abi_tag_field, platform_tag_field = parts
    python_tags = python_tag_field.split(".")
    abi_tags = abi_tag_field.split(".")
    platform_tags = platform_tag_field.split(".")
    expanded = {
        f"{python_tag}-{abi_tag}-{platform_tag}"
        for python_tag in python_tags
        for abi_tag in abi_tags
        for platform_tag in platform_tags
    }
    return distribution, version, python_tags, abi_tags, platform_tags, expanded


def _license_destination(normalized_name: str, member: str) -> PurePosixPath:
    marker = ".dist-info/licenses/"
    if marker in member:
        relative = PurePosixPath(member.split(marker, 1)[1])
    else:
        relative = PurePosixPath(PurePosixPath(member).name)
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise RuntimeSourceError(f"unsafe license member: {member}")
    return PurePosixPath("licenses", normalized_name, *relative.parts)


def _runtime_schema() -> dict[str, Any]:
    hash_schema = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    string_array = {
        "type": "array",
        "items": {"type": "string", "minLength": 1},
        "uniqueItems": True,
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://example.invalid/lto-archiver/runtime-wheel-inventory.schema.json",
        "title": "LTO Archiver closed Python runtime wheel inventory",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "runtime", "wheels"],
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "runtime": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "name",
                    "version",
                    "python_version",
                    "architecture",
                    "aggregate_license",
                    "wheel_count",
                    "source_date_epoch",
                    "authorized_lock_sha256",
                ],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "version": {"type": "string", "minLength": 1},
                    "python_version": {"const": "3.11"},
                    "architecture": {"const": "x86_64"},
                    "aggregate_license": {"type": "string", "minLength": 1},
                    "wheel_count": {"type": "integer", "minimum": 1},
                    "source_date_epoch": {"type": "integer", "minimum": 0},
                    "authorized_lock_sha256": hash_schema,
                },
            },
            "wheels": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "filename",
                        "sha256",
                        "name",
                        "normalized_name",
                        "version",
                        "python_tags",
                        "abi_tags",
                        "platform_tags",
                        "wheel_tags",
                        "root_is_purelib",
                        "architecture",
                        "license_expression",
                        "license_files",
                        "dependencies",
                        "metadata_requires_dist",
                    ],
                    "properties": {
                        "filename": {"type": "string", "pattern": "^[^/]+\\.whl$"},
                        "sha256": hash_schema,
                        "name": {"type": "string", "minLength": 1},
                        "normalized_name": {"type": "string", "minLength": 1},
                        "version": {"type": "string", "minLength": 1},
                        "python_tags": string_array,
                        "abi_tags": string_array,
                        "platform_tags": string_array,
                        "wheel_tags": string_array,
                        "root_is_purelib": {"type": "boolean"},
                        "architecture": {"enum": ["noarch", "x86_64"]},
                        "license_expression": {"type": "string", "minLength": 1},
                        "license_files": {
                            "type": "array",
                            "minItems": 1,
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": ["wheel_member", "path", "sha256"],
                                "properties": {
                                    "wheel_member": {"type": "string", "minLength": 1},
                                    "path": {"type": "string", "minLength": 1},
                                    "sha256": hash_schema,
                                },
                            },
                        },
                        "dependencies": string_array,
                        "metadata_requires_dist": string_array,
                    },
                },
            },
        },
    }


def _spdx_id(normalized_name: str) -> str:
    return "SPDXRef-Package-" + re.sub(r"[^A-Za-z0-9.-]", "-", normalized_name)


def _require_exact_keys(value: Any, expected: set[str], context: str) -> None:
    if not isinstance(value, dict):
        raise RuntimeSourceError(f"{context} must be an object")
    unknown = sorted(set(value) - expected)
    missing = sorted(expected - set(value))
    if unknown:
        raise RuntimeSourceError(f"unknown inventory field in {context}: {unknown}")
    if missing:
        raise RuntimeSourceError(f"missing inventory field in {context}: {missing}")


def _validate_inventory_shape(inventory: Any) -> None:
    _require_exact_keys(inventory, INVENTORY_KEYS, "inventory")
    _require_exact_keys(inventory["runtime"], RUNTIME_KEYS, "runtime")
    if inventory["schema_version"] != SCHEMA_VERSION:
        raise RuntimeSourceError("unsupported wheel inventory schema")
    if not isinstance(inventory["wheels"], list) or not inventory["wheels"]:
        raise RuntimeSourceError("wheel inventory must contain wheels")
    for index, component in enumerate(inventory["wheels"]):
        _require_exact_keys(component, WHEEL_KEYS, f"wheels[{index}]")
        if (
            not isinstance(component["license_files"], list)
            or not component["license_files"]
        ):
            raise RuntimeSourceError(
                f"wheels[{index}].license_files must contain at least one file"
            )
        for license_index, license_file in enumerate(component["license_files"]):
            _require_exact_keys(
                license_file,
                LICENSE_FILE_KEYS,
                f"wheels[{index}].license_files[{license_index}]",
            )
    runtime = inventory["runtime"]
    if runtime["python_version"] != "3.11" or runtime["architecture"] != "x86_64":
        raise RuntimeSourceError("runtime target must be CPython 3.11 on x86_64")
    if runtime["aggregate_license"] != RUNTIME_LICENSE:
        raise RuntimeSourceError("runtime aggregate license mismatch")
    if (
        not isinstance(runtime["source_date_epoch"], int)
        or runtime["source_date_epoch"] < 0
        or not SHA256_PATTERN.fullmatch(runtime["authorized_lock_sha256"])
    ):
        raise RuntimeSourceError("invalid runtime hash or epoch")
    names = {component["normalized_name"] for component in inventory["wheels"]}
    excluded = sorted(names & EXCLUDED_RUNTIME_PROJECTS)
    if excluded:
        raise RuntimeSourceError(f"build tools present in runtime closure: {excluded}")
    for index, component in enumerate(inventory["wheels"]):
        if component["license_expression"] not in COMPONENT_LICENSES:
            raise RuntimeSourceError(
                f"wheels[{index}] has an unsupported license identity"
            )
        if not SHA256_PATTERN.fullmatch(component["sha256"]):
            raise RuntimeSourceError(f"wheels[{index}] has an invalid SHA-256")
        for key in (
            "abi_tags",
            "dependencies",
            "metadata_requires_dist",
            "platform_tags",
            "python_tags",
            "wheel_tags",
        ):
            value = component[key]
            if not isinstance(value, list) or any(
                not isinstance(item, str) or not item for item in value
            ):
                raise RuntimeSourceError(f"wheels[{index}].{key} must be strings")
            if len(value) != len(set(value)):
                raise RuntimeSourceError(f"wheels[{index}].{key} contains duplicates")
        if component["dependencies"] != sorted(component["dependencies"]):
            raise RuntimeSourceError(
                f"wheels[{index}].dependencies is not canonically ordered"
            )
        missing_dependencies = sorted(set(component["dependencies"]) - names)
        if missing_dependencies:
            raise RuntimeSourceError(
                f"{component['filename']}: dependencies outside closure: "
                f"{missing_dependencies}"
            )
        for license_file in component["license_files"]:
            expected_prefix = f"licenses/{component['normalized_name']}/"
            if not license_file["path"].startswith(expected_prefix):
                raise RuntimeSourceError(
                    f"{component['filename']}: noncanonical license path"
                )
            if not SHA256_PATTERN.fullmatch(license_file["sha256"]):
                raise RuntimeSourceError(
                    f"{component['filename']}: invalid license SHA-256"
                )


def _validate_architecture(component: dict[str, Any]) -> None:
    filename = component["filename"]
    if component["root_is_purelib"]:
        if component["architecture"] != "noarch":
            raise RuntimeSourceError(
                f"{filename}: architecture mismatch for pure wheel"
            )
        if component["platform_tags"] != ["any"]:
            raise RuntimeSourceError(f"{filename}: pure wheel has a platform tag")
    else:
        if component["architecture"] != "x86_64":
            raise RuntimeSourceError(
                f"{filename}: architecture mismatch for native wheel"
            )
        if not all(tag.endswith("_x86_64") for tag in component["platform_tags"]):
            raise RuntimeSourceError(f"{filename}: native wheel is not x86_64")
        supported_tag = any(
            python_tag == "cp311" or (python_tag == "cp310" and abi_tag == "abi3")
            for python_tag in component["python_tags"]
            for abi_tag in component["abi_tags"]
        )
        if not supported_tag:
            raise RuntimeSourceError(
                f"{filename}: wheel is incompatible with CPython 3.11"
            )


def _make_sbom(inventory: dict[str, Any]) -> dict[str, Any]:
    runtime = inventory["runtime"]
    packages = []
    relationships = []
    for component in inventory["wheels"]:
        package_id = _spdx_id(component["normalized_name"])
        packages.append(
            {
                "SPDXID": package_id,
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": component["sha256"]}
                ],
                "copyrightText": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": component["license_expression"],
                "licenseDeclared": component["license_expression"],
                "name": component["name"],
                "versionInfo": component["version"],
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": package_id,
            }
        )
        for dependency in component["dependencies"]:
            relationships.append(
                {
                    "spdxElementId": package_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": _spdx_id(dependency),
                }
            )
    created = datetime.fromtimestamp(runtime["source_date_epoch"], UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: lto-archiver-runtime-source"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": (
            "https://example.invalid/spdx/lto-archiver-python-runtime/"
            f"{runtime['version']}/{runtime['authorized_lock_sha256']}"
        ),
        "name": f"{runtime['name']}-{runtime['version']}",
        "packages": packages,
        "relationships": sorted(
            relationships,
            key=lambda item: (
                item["spdxElementId"],
                item["relationshipType"],
                item["relatedSpdxElement"],
            ),
        ),
        "spdxVersion": "SPDX-2.3",
    }


def _make_notices(inventory: dict[str, Any]) -> bytes:
    lines = [
        "# LTO Archiver Python Runtime — Third-Party Notices",
        "",
        "This sealed offline runtime contains the following distributions.",
        "",
    ]
    for component in inventory["wheels"]:
        lines.extend(
            [
                f"## {component['name']} {component['version']}",
                "",
                f"License: {component['license_expression']}",
                "",
            ]
        )
        for license_file in component["license_files"]:
            lines.append(
                f"- `{license_file['path']}` (SHA-256: `{license_file['sha256']}`)"
            )
        lines.append("")
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")


def seal_source(
    authority_path: Path,
    authorized_lock_path: Path,
    wheelhouse: Path,
    output: Path,
    source_date_epoch: int,
) -> None:
    if output.exists() or output.is_symlink():
        raise RuntimeSourceError(f"output already exists: {output}")
    authority = load_json(authority_path)
    runtime = authority["runtime"]
    components = authority["components"]
    if authority.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeSourceError("unsupported component authority schema")
    if sha256_file(authorized_lock_path) != runtime.get("authorized_lock_sha256"):
        raise RuntimeSourceError("authorized lock SHA-256 does not match authority")
    if runtime["expected_wheel_count"] != len(components):
        raise RuntimeSourceError("component authority wheel count mismatch")
    components = sorted(components, key=lambda item: item["filename"])
    authorized_lock = parse_hash_lock(authorized_lock_path)
    expected_filenames = {component["filename"] for component in components}
    actual_filenames = {path.name for path in wheelhouse.glob("*.whl")}
    if actual_filenames != expected_filenames:
        missing = sorted(expected_filenames - actual_filenames)
        extra = sorted(actual_filenames - expected_filenames)
        raise RuntimeSourceError(
            f"wheelhouse closure mismatch: missing={missing} extra={extra}"
        )

    staging_parent = output.parent
    staging_parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.staging.", dir=staging_parent)
    )
    try:
        inventory_wheels = []
        for component in components:
            wheel_path = wheelhouse / component["filename"]
            digest = sha256_file(wheel_path)
            lock_key = (component["normalized_name"], component["version"])
            if digest not in authorized_lock.get(lock_key, set()):
                raise RuntimeSourceError(
                    f"{component['filename']}: SHA-256 is absent from authorized lock"
                )
            inspected = inspect_wheel(wheel_path)
            (
                filename_distribution,
                filename_version,
                py_tags,
                abi_tags,
                platform_tags,
                expanded_tags,
            ) = filename_tags(component["filename"])
            expected_identity = {
                "name": component["name"],
                "normalized_name": component["normalized_name"],
                "version": component["version"],
                "root_is_purelib": component["root_is_purelib"],
                "wheel_tags": component["wheel_tags"],
                "license_expression": component["license_expression"],
            }
            actual_identity = {key: inspected[key] for key in expected_identity}
            if actual_identity != expected_identity:
                raise RuntimeSourceError(
                    f"{component['filename']}: wheel identity does not match authority"
                )
            if (
                normalize_name(filename_distribution) != component["normalized_name"]
                or filename_version != component["version"]
            ):
                raise RuntimeSourceError(
                    f"{component['filename']}: filename name/version does not match authority"
                )
            if sorted(component["license_members"]) != inspected["license_members"]:
                raise RuntimeSourceError(
                    f"{component['filename']}: license member inventory mismatch"
                )
            if (
                py_tags != component["python_tags"]
                or abi_tags != component["abi_tags"]
                or platform_tags != component["platform_tags"]
                or expanded_tags != set(component["wheel_tags"])
            ):
                raise RuntimeSourceError(
                    f"{component['filename']}: filename tags do not match authority"
                )
            copied_wheel = staging / "wheels" / component["filename"]
            copied_wheel.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(wheel_path, copied_wheel)
            license_files = []
            for member in component["license_members"]:
                if member not in inspected["members"]:
                    raise RuntimeSourceError(
                        f"{component['filename']}: missing license member {member}"
                    )
                content = inspected["members"][member]
                destination = _license_destination(component["normalized_name"], member)
                destination_path = staging / Path(*destination.parts)
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                destination_path.write_bytes(content)
                license_files.append(
                    {
                        "path": destination.as_posix(),
                        "sha256": sha256_bytes(content),
                        "wheel_member": member,
                    }
                )
            inventory_wheels.append(
                {
                    "abi_tags": component["abi_tags"],
                    "architecture": component["architecture"],
                    "dependencies": sorted(component["dependencies"]),
                    "filename": component["filename"],
                    "license_expression": component["license_expression"],
                    "license_files": license_files,
                    "metadata_requires_dist": inspected["metadata_requires_dist"],
                    "name": component["name"],
                    "normalized_name": component["normalized_name"],
                    "platform_tags": component["platform_tags"],
                    "python_tags": component["python_tags"],
                    "root_is_purelib": component["root_is_purelib"],
                    "sha256": digest,
                    "version": component["version"],
                    "wheel_tags": component["wheel_tags"],
                }
            )
        inventory = {
            "runtime": {
                "aggregate_license": runtime["aggregate_license"],
                "architecture": runtime["architecture"],
                "authorized_lock_sha256": sha256_file(authorized_lock_path),
                "name": runtime["name"],
                "python_version": runtime["python_version"],
                "source_date_epoch": source_date_epoch,
                "version": runtime["version"],
                "wheel_count": len(inventory_wheels),
            },
            "schema_version": SCHEMA_VERSION,
            "wheels": inventory_wheels,
        }
        exact_lock = "".join(
            f"{component['normalized_name']}=={component['version']} "
            f"--hash=sha256:{component['sha256']}\n"
            for component in inventory_wheels
        ).encode("utf-8")
        (staging / "requirements-runtime.lock").write_bytes(exact_lock)
        (staging / "wheel-inventory.schema.json").write_bytes(
            canonical_json(_runtime_schema())
        )
        (staging / "wheel-inventory.json").write_bytes(canonical_json(inventory))
        (staging / "runtime.spdx.json").write_bytes(
            canonical_json(_make_sbom(inventory))
        )
        (staging / "THIRD_PARTY_NOTICES.md").write_bytes(_make_notices(inventory))
        tool_destination = staging / "tools" / "runtime_source.py"
        tool_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(__file__), tool_destination)
        _verify_source_against_trusted(staging, inventory, Path(__file__))
        output.parent.mkdir(parents=True, exist_ok=True)
        staging.rename(output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _verify_source_against_trusted(
    source: Path, trusted_inventory: dict[str, Any], trusted_tool: Path
) -> None:
    _validate_inventory_shape(trusted_inventory)
    inventory_path = source / "wheel-inventory.json"
    inventory = load_json(inventory_path)
    if inventory_path.read_bytes() != canonical_json(inventory):
        raise RuntimeSourceError("wheel inventory is not canonical")
    if inventory != trusted_inventory:
        raise RuntimeSourceError("sealed inventory does not match trusted authority")
    if not trusted_tool.is_file() or trusted_tool.is_symlink():
        raise RuntimeSourceError("trusted runtime source tool is not a regular file")
    embedded_tool = source / "tools" / "runtime_source.py"
    if (
        not embedded_tool.is_file()
        or embedded_tool.is_symlink()
        or sha256_file(embedded_tool) != sha256_file(trusted_tool)
    ):
        raise RuntimeSourceError("embedded runtime source tool mismatch")
    inventory = trusted_inventory
    wheels = inventory.get("wheels")
    runtime = inventory.get("runtime")
    if not isinstance(wheels, list) or not isinstance(runtime, dict):
        raise RuntimeSourceError("malformed wheel inventory")
    if runtime.get("wheel_count") != len(wheels):
        raise RuntimeSourceError("wheel inventory count mismatch")
    if wheels != sorted(wheels, key=lambda item: item["filename"]):
        raise RuntimeSourceError("wheel inventory is not canonically ordered")
    expected_wheels = {component["filename"] for component in wheels}
    actual_wheels = {path.name for path in (source / "wheels").glob("*.whl")}
    if expected_wheels != actual_wheels:
        raise RuntimeSourceError(
            "wheel closure mismatch: "
            f"missing={sorted(expected_wheels - actual_wheels)} "
            f"extra={sorted(actual_wheels - expected_wheels)}"
        )
    seen_names: set[str] = set()
    for component in wheels:
        normalized_name = component["normalized_name"]
        if normalized_name in seen_names:
            raise RuntimeSourceError(f"duplicate distribution: {normalized_name}")
        seen_names.add(normalized_name)
        _validate_architecture(component)
        wheel = source / "wheels" / component["filename"]
        if sha256_file(wheel) != component["sha256"]:
            raise RuntimeSourceError(f"{wheel.name}: SHA-256 mismatch")
        inspected = inspect_wheel(wheel)
        for key in (
            "name",
            "normalized_name",
            "version",
            "root_is_purelib",
            "wheel_tags",
            "license_expression",
            "metadata_requires_dist",
        ):
            if inspected[key] != component[key]:
                raise RuntimeSourceError(f"{wheel.name}: {key} mismatch")
        if normalize_name(component["name"]) != normalized_name:
            raise RuntimeSourceError(
                f"{component['filename']}: noncanonical project name"
            )
        (
            filename_distribution,
            filename_version,
            py_tags,
            abi_tags,
            platform_tags,
            expanded_tags,
        ) = filename_tags(wheel.name)
        if (
            normalize_name(filename_distribution) != normalized_name
            or filename_version != component["version"]
        ):
            raise RuntimeSourceError(f"{wheel.name}: filename name/version mismatch")
        if py_tags != component["python_tags"]:
            raise RuntimeSourceError(f"{wheel.name}: Python tag mismatch")
        if abi_tags != component["abi_tags"]:
            raise RuntimeSourceError(f"{wheel.name}: ABI tag mismatch")
        if platform_tags != component["platform_tags"]:
            raise RuntimeSourceError(f"{wheel.name}: platform tag mismatch")
        if expanded_tags != set(component["wheel_tags"]):
            raise RuntimeSourceError(f"{wheel.name}: WHEEL tag mismatch")
        for license_file in component["license_files"]:
            path = source / license_file["path"]
            if not path.is_file():
                raise RuntimeSourceError(
                    f"{wheel.name}: missing license file {license_file['path']}"
                )
            if sha256_file(path) != license_file["sha256"]:
                raise RuntimeSourceError(
                    f"{wheel.name}: license SHA-256 mismatch {license_file['path']}"
                )
            member = license_file["wheel_member"]
            if member not in inspected["members"]:
                raise RuntimeSourceError(
                    f"{wheel.name}: missing wheel license {member}"
                )
            if sha256_bytes(inspected["members"][member]) != license_file["sha256"]:
                raise RuntimeSourceError(
                    f"{wheel.name}: wheel license SHA-256 mismatch"
                )
    expected_lock = {
        (component["normalized_name"], component["version"]): {component["sha256"]}
        for component in wheels
    }
    if parse_hash_lock(source / "requirements-runtime.lock") != expected_lock:
        raise RuntimeSourceError("runtime hash lock does not match inventory")
    if (source / "wheel-inventory.schema.json").read_bytes() != canonical_json(
        _runtime_schema()
    ):
        raise RuntimeSourceError("wheel inventory schema is not canonical")
    if (source / "runtime.spdx.json").read_bytes() != canonical_json(
        _make_sbom(inventory)
    ):
        raise RuntimeSourceError("SPDX SBOM does not match inventory")
    if (source / "THIRD_PARTY_NOTICES.md").read_bytes() != _make_notices(inventory):
        raise RuntimeSourceError("third-party notices do not match inventory")
    expected_files = {
        "THIRD_PARTY_NOTICES.md",
        "requirements-runtime.lock",
        "runtime.spdx.json",
        "tools/runtime_source.py",
        "wheel-inventory.json",
        "wheel-inventory.schema.json",
    }
    expected_files.update(f"wheels/{component['filename']}" for component in wheels)
    expected_files.update(
        license_file["path"]
        for component in wheels
        for license_file in component["license_files"]
    )
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for path in source.rglob("*"):
        relative = path.relative_to(source).as_posix()
        if path.is_symlink():
            raise RuntimeSourceError(f"source contains a symlink: {relative}")
        if path.is_file():
            actual_files.add(relative)
        elif path.is_dir():
            actual_directories.add(relative)
        else:
            raise RuntimeSourceError(f"source contains a special file: {relative}")
    if actual_files != expected_files:
        raise RuntimeSourceError(
            "source file closure mismatch: "
            f"missing={sorted(expected_files - actual_files)} "
            f"extra={sorted(actual_files - expected_files)}"
        )
    expected_directories: set[str] = set()
    for filename in expected_files:
        parent = PurePosixPath(filename).parent
        while parent != PurePosixPath("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    if actual_directories != expected_directories:
        raise RuntimeSourceError(
            "source directory closure mismatch: "
            f"missing={sorted(expected_directories - actual_directories)} "
            f"extra={sorted(actual_directories - expected_directories)}"
        )


def verify_source(source: Path, authority_root: Path) -> None:
    verify_authority(authority_root)
    trusted_inventory = load_json(authority_root / "wheel-inventory.json")
    _verify_source_against_trusted(
        source, trusted_inventory, authority_root / "runtime_source.py"
    )


def verify_authority(authority_root: Path) -> None:
    binary_paths = sorted(
        path.relative_to(authority_root).as_posix()
        for path in authority_root.rglob("*")
        if path.is_file() and path.name.endswith((".whl", ".tar.gz"))
    )
    if binary_paths:
        raise RuntimeSourceError(
            f"runtime binaries committed in authority: {binary_paths}"
        )
    inventory = load_json(authority_root / "wheel-inventory.json")
    _validate_inventory_shape(inventory)
    wheels = inventory["wheels"]
    if wheels != sorted(wheels, key=lambda item: item["filename"]):
        raise RuntimeSourceError("wheel inventory is not canonically ordered")
    seen_names: set[str] = set()
    for component in wheels:
        normalized_name = component["normalized_name"]
        if normalized_name in seen_names:
            raise RuntimeSourceError(f"duplicate distribution: {normalized_name}")
        seen_names.add(normalized_name)
        _validate_architecture(component)
        for license_file in component["license_files"]:
            path = authority_root / license_file["path"]
            if not path.is_file() or path.is_symlink():
                raise RuntimeSourceError(
                    f"{component['filename']}: missing license file {license_file['path']}"
                )
            if sha256_file(path) != license_file["sha256"]:
                raise RuntimeSourceError(
                    f"{component['filename']}: license SHA-256 mismatch "
                    f"{license_file['path']}"
                )
    expected_lock = {
        (component["normalized_name"], component["version"]): {component["sha256"]}
        for component in wheels
    }
    if parse_hash_lock(authority_root / "requirements-runtime.lock") != expected_lock:
        raise RuntimeSourceError("runtime hash lock does not match inventory")
    if (authority_root / "wheel-inventory.schema.json").read_bytes() != canonical_json(
        _runtime_schema()
    ):
        raise RuntimeSourceError("wheel inventory schema is not canonical")
    if (authority_root / "wheel-inventory.json").read_bytes() != canonical_json(
        inventory
    ):
        raise RuntimeSourceError("wheel inventory is not canonical")
    if (authority_root / "runtime.spdx.json").read_bytes() != canonical_json(
        _make_sbom(inventory)
    ):
        raise RuntimeSourceError("SPDX SBOM does not match inventory")
    if (authority_root / "THIRD_PARTY_NOTICES.md").read_bytes() != _make_notices(
        inventory
    ):
        raise RuntimeSourceError("third-party notices do not match inventory")
    expected_licenses = {
        license_file["path"]
        for component in wheels
        for license_file in component["license_files"]
    }
    actual_licenses = {
        path.relative_to(authority_root).as_posix()
        for path in (authority_root / "licenses").rglob("*")
        if path.is_file()
    }
    if actual_licenses != expected_licenses:
        raise RuntimeSourceError(
            "license file closure mismatch: "
            f"missing={sorted(expected_licenses - actual_licenses)} "
            f"extra={sorted(actual_licenses - expected_licenses)}"
        )
    component_authority = load_json(authority_root / "runtime-components.json")
    component_runtime = component_authority.get("runtime")
    if not isinstance(component_runtime, dict):
        raise RuntimeSourceError("component authority runtime is malformed")
    components = sorted(
        component_authority["components"], key=lambda item: item["filename"]
    )
    if (
        component_authority.get("schema_version") != SCHEMA_VERSION
        or len(components) != component_authority["runtime"]["expected_wheel_count"]
    ):
        raise RuntimeSourceError("component authority count or schema mismatch")
    authorized_lock_sha256 = parse_digest_file(
        authority_root / "authorized-lock.sha256", "requirements-runtime.lock"
    )
    public_lock = authority_root / "requirements-runtime.lock"
    if (
        not public_lock.is_file()
        or public_lock.is_symlink()
        or sha256_file(public_lock) != authorized_lock_sha256
    ):
        raise RuntimeSourceError("authorized lock bytes do not match authority")
    if (
        authorized_lock_sha256 != component_runtime.get("authorized_lock_sha256")
        or authorized_lock_sha256 != inventory["runtime"]["authorized_lock_sha256"]
    ):
        raise RuntimeSourceError("authorized lock digest authority mismatch")
    runtime_keys = (
        "aggregate_license",
        "architecture",
        "name",
        "python_version",
        "version",
    )
    if any(
        component_runtime.get(key) != inventory["runtime"].get(key)
        for key in runtime_keys
    ) or component_runtime.get("expected_wheel_count") != inventory["runtime"].get(
        "wheel_count"
    ):
        raise RuntimeSourceError("component runtime authority does not match inventory")
    inventory_by_filename = {component["filename"]: component for component in wheels}
    if set(inventory_by_filename) != {
        component["filename"] for component in components
    }:
        raise RuntimeSourceError("component authority filenames do not match inventory")
    identity_keys = (
        "abi_tags",
        "architecture",
        "dependencies",
        "filename",
        "license_expression",
        "name",
        "normalized_name",
        "platform_tags",
        "python_tags",
        "root_is_purelib",
        "version",
        "wheel_tags",
    )
    for component in components:
        inventory_component = inventory_by_filename[component["filename"]]
        if any(
            component[key] != inventory_component[key] for key in identity_keys
        ) or sorted(component["license_members"]) != sorted(
            item["wheel_member"] for item in inventory_component["license_files"]
        ):
            raise RuntimeSourceError(
                f"{component['filename']}: component authority mismatch"
            )


def _source0_prefix(source: Path) -> str:
    inventory = load_json(source / "wheel-inventory.json")
    runtime = inventory["runtime"]
    return f"{runtime['name']}-{runtime['version']}"


def _source0_entries(source: Path) -> list[tuple[Path, str]]:
    prefix = _source0_prefix(source)
    entries = [(source, prefix)]
    entries.extend(
        (path, f"{prefix}/{path.relative_to(source).as_posix()}")
        for path in source.rglob("*")
    )
    return sorted(entries, key=lambda item: item[1])


def _write_source0(source: Path, output: Path, source_date_epoch: int) -> None:
    with (
        output.open("wb") as raw_output,
        gzip.GzipFile(
            filename="", mode="wb", fileobj=raw_output, mtime=source_date_epoch
        ) as compressed,
        tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT
        ) as archive,
    ):
        for path, archive_name in _source0_entries(source):
            if path.is_symlink():
                raise RuntimeSourceError(
                    f"source contains a symlink: {path.relative_to(source)}"
                )
            info = tarfile.TarInfo(archive_name)
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = source_date_epoch
            if path.is_dir():
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.size = 0
                archive.addfile(info)
            elif path.is_file():
                info.type = tarfile.REGTYPE
                info.mode = 0o644
                info.size = path.stat().st_size
                with path.open("rb") as payload:
                    archive.addfile(info, payload)
            else:
                raise RuntimeSourceError(
                    f"source contains a special file: {path.relative_to(source)}"
                )


def build_source0(
    source: Path, output: Path, source_date_epoch: int, authority_root: Path
) -> None:
    if output.exists() or output.is_symlink():
        raise RuntimeSourceError(f"output already exists: {output}")
    verify_source(source, authority_root)
    inventory_epoch = load_json(authority_root / "wheel-inventory.json")["runtime"][
        "source_date_epoch"
    ]
    if source_date_epoch != inventory_epoch:
        raise RuntimeSourceError("SOURCE_DATE_EPOCH does not match trusted authority")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".partial", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        _write_source0(source, temporary, source_date_epoch)
        temporary.replace(output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def verify_source0(
    source: Path,
    archive: Path,
    source_date_epoch: int,
    expected_sha256: Path,
    authority_root: Path,
) -> None:
    verify_source(source, authority_root)
    trusted_epoch = load_json(authority_root / "wheel-inventory.json")["runtime"][
        "source_date_epoch"
    ]
    if source_date_epoch != trusted_epoch:
        raise RuntimeSourceError("SOURCE_DATE_EPOCH does not match trusted authority")
    if not archive.is_file() or archive.is_symlink():
        raise RuntimeSourceError(f"Source0 is not a regular file: {archive}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix="runtime-source0-", suffix=".tar.gz"
    )
    os.close(descriptor)
    canonical = Path(temporary_name)
    try:
        _write_source0(source, canonical, source_date_epoch)
        if archive.read_bytes() != canonical.read_bytes():
            raise RuntimeSourceError("noncanonical Source0 archive")
    finally:
        canonical.unlink(missing_ok=True)
    expected_digest = parse_digest_file(expected_sha256, archive.name)
    if sha256_file(archive) != expected_digest:
        raise RuntimeSourceError("Source0 SHA-256 mismatch")


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    seal = commands.add_parser("seal", help="seal an authorized wheelhouse")
    seal.add_argument("--authority", type=Path, required=True)
    seal.add_argument("--authorized-lock", type=Path, required=True)
    seal.add_argument("--wheelhouse", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    seal.add_argument("--source-date-epoch", type=int, required=True)
    verify = commands.add_parser("verify-source", help="verify a sealed source tree")
    verify.add_argument("--source", type=Path, required=True)
    verify.add_argument("--authority-root", type=Path, required=True)
    verify_committed = commands.add_parser(
        "verify-authority", help="verify committed non-binary runtime authority"
    )
    verify_committed.add_argument("--authority-root", type=Path, required=True)
    build = commands.add_parser("build-source0", help="build canonical Source0")
    build.add_argument("--source", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--source-date-epoch", type=int, required=True)
    build.add_argument("--authority-root", type=Path, required=True)
    verify_archive = commands.add_parser(
        "verify-source0", help="verify canonical Source0"
    )
    verify_archive.add_argument("--source", type=Path, required=True)
    verify_archive.add_argument("--archive", type=Path, required=True)
    verify_archive.add_argument("--source-date-epoch", type=int, required=True)
    verify_archive.add_argument("--expected-sha256", type=Path, required=True)
    verify_archive.add_argument("--authority-root", type=Path, required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _argument_parser().parse_args(arguments)
    try:
        if options.command == "seal":
            seal_source(
                options.authority,
                options.authorized_lock,
                options.wheelhouse,
                options.output,
                options.source_date_epoch,
            )
        elif options.command == "verify-source":
            verify_source(options.source, options.authority_root)
        elif options.command == "verify-authority":
            verify_authority(options.authority_root)
        elif options.command == "build-source0":
            build_source0(
                options.source,
                options.output,
                options.source_date_epoch,
                options.authority_root,
            )
        elif options.command == "verify-source0":
            verify_source0(
                options.source,
                options.archive,
                options.source_date_epoch,
                options.expected_sha256,
                options.authority_root,
            )
        else:  # pragma: no cover - argparse enforces this branch.
            raise RuntimeSourceError(f"unsupported command: {options.command}")
    except RuntimeSourceError as error:
        print(f"runtime source error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
