from __future__ import annotations

import ipaddress
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .errors import ValidationError

_SHARE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
SHARE_SAFE_ERROR_CODES = frozenset(
    {
        "idempotency_conflict",
        "share_authentication_failed",
        "share_broker_unavailable",
        "share_busy",
        "share_connected",
        "share_credentials_required",
        "share_endpoint_invalid",
        "share_endpoint_not_allowed",
        "share_has_libraries",
        "share_identity_changed",
        "share_in_use",
        "share_mount_authorization_failed",
        "share_mount_failed",
        "share_not_found",
        "share_operation_timeout",
        "share_options_invalid",
        "share_recovery_required",
        "share_revision_conflict",
        "share_state_conflict",
        "share_unreachable",
    }
)


class ShareValidationError(ValidationError):
    """A network-share value violates the closed safe contract."""


def normalize_share_id(value: str) -> str:
    """Return a safe, case-insensitive share identity for a mount directory."""

    normalized = _normalized_text(value, "share ID").casefold()
    if not _SHARE_ID.fullmatch(normalized):
        raise ShareValidationError("share ID must be a safe mount name")
    return normalized


def validate_share_safe_error_code(value: str | None) -> str | None:
    """Accept only public share failures that are safe to persist and return."""

    if value is None:
        return None
    if not isinstance(value, str) or value not in SHARE_SAFE_ERROR_CODES:
        raise ShareValidationError("share error code is not allowlisted")
    return value


def normalize_server(value: str) -> str:
    """Normalize a literal IP or DNS name without performing DNS resolution."""

    normalized = _normalized_text(value, "server")
    if any(character in normalized for character in ("@", "/", "\\", "://")):
        raise ShareValidationError(
            "server must be a DNS name or IP literal without userinfo"
        )
    if "%" in normalized:
        raise ShareValidationError("server IP literals must not include a zone")

    try:
        return str(ipaddress.ip_address(normalized))
    except ValueError:
        pass

    if ":" in normalized:
        raise ShareValidationError("server must not include a port")
    hostname = normalized.rstrip(".").casefold()
    if not hostname or len(hostname) > 253:
        raise ShareValidationError("server DNS name is invalid")
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ShareValidationError("server DNS name is invalid") from exc
    if not all(_DNS_LABEL.fullmatch(label) for label in hostname.split(".")):
        raise ShareValidationError("server DNS name is invalid")
    return hostname


def derive_mount_target(root: Path, share_id: str) -> Path:
    """Derive the only permitted target beneath a deployment-owned root."""

    root = Path(root)
    if not root.is_absolute():
        raise ShareValidationError("managed source mount root must be absolute")
    normalized_id = normalize_share_id(share_id)
    target = root / normalized_id
    if not target.is_relative_to(root):  # defensive: normalization already prevents this
        raise ShareValidationError(
            "derived mount target escapes managed source mount root"
        )
    return target


NFS_VERSION_CHOICES = ("3", "4", "4.1", "4.2")
NFS_TIMEOUT_SECONDS_CHOICES = (5, 15, 30, 60, 120, 300, 600)
NFS_RETRANSMISSION_CHOICES = (1, 2, 3, 5, 10)
SMB_DIALECT_CHOICES = ("3.0", "3.1.1")


class NfsShareConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["nfs"]
    server: str
    export: str
    version: Literal["3", "4", "4.1", "4.2"] = "4.2"
    timeout_seconds: Literal[5, 15, 30, 60, 120, 300, 600] = 60
    retransmissions: Literal[1, 2, 3, 5, 10] = 2

    @field_validator("server")
    @classmethod
    def normalize_server_field(cls, value: str) -> str:
        return _model_value(normalize_server, value)

    @field_validator("export")
    @classmethod
    def normalize_export(cls, value: str) -> str:
        try:
            export = _normalized_text(value, "NFS export")
        except ShareValidationError as exc:
            raise ValueError(str(exc)) from exc
        if not export.startswith("/") or "\\" in export:
            raise ValueError("NFS export must be an absolute POSIX path")
        parts = PurePosixPath(export).parts
        if any(part in {".", ".."} for part in parts):
            raise ValueError("NFS export must not contain traversal")
        return str(PurePosixPath(export))


class SmbShareConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["smb"]
    server: str
    share: str
    dialect: Literal["3.0", "3.1.1"] = "3.1.1"
    encryption_required: bool = True

    @field_validator("server")
    @classmethod
    def normalize_server_field(cls, value: str) -> str:
        return _model_value(normalize_server, value)

    @field_validator("share")
    @classmethod
    def normalize_share(cls, value: str) -> str:
        try:
            share = _normalized_text(value, "SMB share")
        except ShareValidationError as exc:
            raise ValueError(str(exc)) from exc
        if share in {".", ".."} or any(character in share for character in ("/", "\\")):
            raise ValueError("SMB share must not contain separators or traversal")
        return share


ShareConfig: TypeAlias = Annotated[
    NfsShareConfig | SmbShareConfig, Field(discriminator="kind")
]


@dataclass(frozen=True)
class EndpointPolicy:
    """Closed endpoint allowlist that rejects mixed DNS answers."""

    cidrs: tuple[str, ...]
    dns_suffixes: tuple[str, ...]
    _networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = field(
        init=False, repr=False
    )

    def __post_init__(self) -> None:
        if not self.cidrs:
            raise ShareValidationError(
                "share endpoint CIDR allowlist must not be empty"
            )
        networks = []
        for cidr in self.cidrs:
            if not isinstance(cidr, str):
                raise ShareValidationError("share endpoint CIDRs must be strings")
            try:
                networks.append(ipaddress.ip_network(cidr, strict=True))
            except ValueError as exc:
                raise ShareValidationError("share endpoint CIDR is invalid") from exc
        suffixes = tuple(_normalize_dns_suffix(suffix) for suffix in self.dns_suffixes)
        if not suffixes:
            raise ShareValidationError(
                "share endpoint DNS suffix allowlist must not be empty"
            )
        object.__setattr__(self, "cidrs", tuple(self.cidrs))
        object.__setattr__(self, "dns_suffixes", suffixes)
        object.__setattr__(self, "_networks", tuple(networks))

    def admit(
        self,
        server: str,
        resolved: Sequence[ipaddress.IPv4Address | ipaddress.IPv6Address],
    ) -> tuple[str, ...]:
        normalized_server = normalize_server(server)
        is_literal = _is_ip_literal(normalized_server)
        if not is_literal and not any(
            normalized_server.endswith(suffix) for suffix in self.dns_suffixes
        ):
            raise ShareValidationError("share endpoint is not allowed")

        normalized_addresses = []
        for address in resolved:
            if not isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                raise ShareValidationError("resolved share endpoint is invalid")
            if not any(address in network for network in self._networks):
                raise ShareValidationError("share endpoint is not allowed")
            normalized_addresses.append(str(address))
        if not normalized_addresses:
            raise ShareValidationError("share endpoint did not resolve")
        return tuple(normalized_addresses)


def _normalized_text(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise ShareValidationError(f"{field_name} must be a string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ShareValidationError(f"{field_name} must not contain control characters")
    normalized = unicodedata.normalize("NFKC", value).strip()
    if not normalized or any(
        ord(character) < 32 or ord(character) == 127 for character in normalized
    ):
        raise ShareValidationError(f"{field_name} is invalid")
    return normalized


def _model_value(normalizer, value: str) -> str:
    try:
        return normalizer(value)
    except ShareValidationError as exc:
        raise ValueError(str(exc)) from exc


def _normalize_dns_suffix(value: str) -> str:
    suffix = _normalized_text(value, "share endpoint DNS suffix").casefold()
    if not suffix.startswith("."):
        raise ShareValidationError("share endpoint DNS suffix must start with a dot")
    try:
        normalized = suffix[1:].encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ShareValidationError("share endpoint DNS suffix is invalid") from exc
    if not normalized or not all(
        _DNS_LABEL.fullmatch(label) for label in normalized.split(".")
    ):
        raise ShareValidationError("share endpoint DNS suffix is invalid")
    return f".{normalized}"


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
