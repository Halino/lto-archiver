from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import ValidationError
from .shares import ShareConfig, derive_mount_target

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


def normalize_managed_source_subpath(value: object) -> str:
    """Return one unambiguous relative POSIX path below a managed share."""

    if not isinstance(value, str):
        raise ValidationError("network library subpath is invalid")
    normalized = unicodedata.normalize("NFKC", value).strip()
    if not normalized:
        return ""
    parts = normalized.split("/")
    if (
        normalized.startswith("/")
        or _WINDOWS_DRIVE.match(normalized) is not None
        or "\\" in normalized
        or any(part in {"", ".", ".."} for part in parts)
        or any(
            unicodedata.category(character).startswith("C") for character in normalized
        )
    ):
        raise ValidationError("network library subpath is invalid")
    return PurePosixPath(*parts).as_posix()


class ManagedSourceAdmissionError(RuntimeError):
    code = "share_identity_changed"

    def __init__(self) -> None:
        super().__init__(self.code)


def source_directory_identity(root: Path) -> str:
    metadata = root.stat()
    return _directory_identity_digest(str(root), int(metadata.st_dev), int(metadata.st_ino))


def _directory_identity_digest(root: str, device: int, inode: int) -> str:
    encoded = json.dumps(
        {
            "canonical_root": str(root),
            "device": device,
            "inode": inode,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@lru_cache(maxsize=128)
def _prior_nfs_device_matches(
    expected_digest: str, canonical_root: str, current_device: int, inode: int
) -> bool:
    """Prove an old pin, never cache mount admission or ignore directory identity.

    Legacy pins retained only H(path, st_dev, inode). Anonymous NFS device
    numbers are local to a mount lifetime. Recover only that bounded component;
    a different path/inode still cannot match the historical digest. Larger old
    device numbers fail closed instead of causing unbounded work.
    """
    if os.major(current_device) != 0:
        return False
    for minor in range(4096):
        if _directory_identity_digest(canonical_root, os.makedev(0, minor), inode) == expected_digest:
            return True
    return False


def _matches_renumbered_nfs_root(
    expected: Mapping[str, Any], observed: Mapping[str, Any], root: Path
) -> bool:
    """Compatibility only after fresh broker verification of an exact NFS root."""
    if (
        observed.get("relative_subpath") != ""
        or observed.get("filesystem_type") not in {"nfs", "nfs4"}
        or observed.get("read_only") is not True
        or {**observed, "source_identity_sha256": expected["source_identity_sha256"]}
        != expected
    ):
        return False
    metadata = root.stat()
    current_digest = _directory_identity_digest(
        str(root), int(metadata.st_dev), int(metadata.st_ino)
    )
    if current_digest != observed["source_identity_sha256"]:
        return False
    return _prior_nfs_device_matches(
        str(expected["source_identity_sha256"]), str(root),
        int(metadata.st_dev), int(metadata.st_ino),
    )


def canonical_managed_source_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    keys = {
        "kind",
        "share_id",
        "resource_revision",
        "config_revision",
        "credential_generation",
        "mount_identity_sha256",
        "read_only",
        "filesystem_type",
        "source_sha256",
        "admitted_endpoints_sha256",
        "relative_subpath",
        "source_identity_sha256",
    }
    if set(value) != keys or value.get("kind") != "managed_share":
        raise ValidationError("invalid managed source evidence")
    normalized = dict(value)
    normalized["relative_subpath"] = normalize_managed_source_subpath(
        normalized["relative_subpath"]
    )
    for key in (
        "mount_identity_sha256",
        "source_sha256",
        "admitted_endpoints_sha256",
        "source_identity_sha256",
    ):
        candidate = normalized.get(key)
        if (
            not isinstance(candidate, str)
            or re.fullmatch(r"[0-9a-f]{64}", candidate) is None
        ):
            raise ValidationError("invalid managed source evidence")
    if (
        type(normalized.get("resource_revision")) is not int
        or normalized["resource_revision"] < 1
        or type(normalized.get("config_revision")) is not int
        or normalized["config_revision"] < 1
        or type(normalized.get("credential_generation")) is not int
        or normalized["credential_generation"] < 0
        or normalized.get("read_only") is not True
        or not isinstance(normalized.get("filesystem_type"), str)
        or not isinstance(normalized.get("share_id"), str)
    ):
        raise ValidationError("invalid managed source evidence")
    return normalized


@dataclass(frozen=True)
class VerifiedManagedSource:
    library_id: str
    derived_root: Path
    evidence: dict[str, Any]


class ManagedSourceVerifier:
    """The only current-vs-frozen admission boundary for managed libraries."""

    def __init__(
        self,
        catalog_path: Path,
        managed_root: Path,
        *,
        parse_config: Callable[[Mapping[str, Any]], ShareConfig],
        inspect_mount: Callable[[Mapping[str, Any], ShareConfig], Any],
    ) -> None:
        self._catalog_path = Path(catalog_path)
        self._managed_root = Path(managed_root)
        self._parse_config = parse_config
        self._inspect_mount = inspect_mount

    def verify_library(
        self,
        library_id: str,
        expected: Mapping[str, Any] | None = None,
    ) -> VerifiedManagedSource:
        try:
            from .catalog import Catalog

            with Catalog(self._catalog_path) as catalog:
                catalog.initialize()
                library = dict(catalog.get_named_library(library_id))
                binding = catalog.get_library_share_binding(library_id)
            if library.get("source_kind") != "network":
                raise ManagedSourceAdmissionError
            verified = self.verify_candidate(
                str(binding["share_id"]),
                str(binding["relative_subpath"]),
                expected=expected,
            )
            return VerifiedManagedSource(
                str(library["id"]), verified.derived_root, verified.evidence
            )
        except ManagedSourceAdmissionError:
            raise
        except Exception:
            raise ManagedSourceAdmissionError from None

    def verify_candidate(
        self,
        share_id: str,
        relative_subpath: str,
        expected: Mapping[str, Any] | None = None,
    ) -> VerifiedManagedSource:
        try:
            from .catalog import Catalog

            with Catalog(self._catalog_path) as catalog:
                catalog.initialize()
                share = catalog.get_managed_share(share_id)
            if (
                share["lifecycle"] != "active"
                or share["desired_state"] != "connected"
                or share["observed_state"] != "connected"
                or share["mount_identity_sha256"] is None
                or int(share["mounted_config_revision"] or 0)
                != int(share["config_revision"])
                or share["mounted_credential_generation"] is None
                or int(share["mounted_credential_generation"])
                != int(share["credential_generation"])
            ):
                raise ManagedSourceAdmissionError
            config = self._parse_config(share)
            receipt = self._inspect_mount(share, config)
            if (
                receipt.result != "mounted"
                or receipt.mount_identity_sha256 != share["mount_identity_sha256"]
            ):
                raise ManagedSourceAdmissionError
            relative_subpath = normalize_managed_source_subpath(relative_subpath)
            lexical_mount = derive_mount_target(
                self._managed_root, str(share["share_id"])
            )
            if lexical_mount.is_symlink():
                raise ManagedSourceAdmissionError
            mount_root = lexical_mount.resolve(strict=True)
            managed_root = self._managed_root.resolve(strict=True)
            if not mount_root.is_relative_to(managed_root):
                raise ManagedSourceAdmissionError
            derived = (mount_root / Path(relative_subpath)).resolve(strict=True)
            if not derived.is_dir() or not derived.is_relative_to(mount_root):
                raise ManagedSourceAdmissionError
            endpoint_digest = hashlib.sha256(
                b"lto-share-admitted-endpoints-v1\0"
                + json.dumps(
                    list(receipt.admitted_addresses), separators=(",", ":")
                ).encode("ascii")
            ).hexdigest()
            evidence = canonical_managed_source_evidence(
                {
                    "kind": "managed_share",
                    "share_id": str(share["share_id"]),
                    "resource_revision": int(share["revision"]),
                    "config_revision": int(receipt.config_revision),
                    "credential_generation": int(receipt.credential_generation),
                    "mount_identity_sha256": str(receipt.mount_identity_sha256),
                    "read_only": bool(receipt.read_only),
                    "filesystem_type": str(receipt.filesystem_type),
                    "source_sha256": str(receipt.source_sha256),
                    "admitted_endpoints_sha256": endpoint_digest,
                    "relative_subpath": relative_subpath,
                    "source_identity_sha256": source_directory_identity(derived),
                }
            )
            if expected is not None:
                frozen = canonical_managed_source_evidence(expected)
                if frozen != evidence:
                    if derived != mount_root or not _matches_renumbered_nfs_root(
                        frozen, evidence, derived
                    ):
                        raise ManagedSourceAdmissionError
                    # Keep all immutable plan/cassette/operation pins byte-equivalent.
                    # Every subsequent call still checks the current broker receipt.
                    evidence = frozen
            return VerifiedManagedSource("", derived, evidence)
        except ManagedSourceAdmissionError:
            raise
        except Exception:
            raise ManagedSourceAdmissionError from None
