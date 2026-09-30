from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from pydantic import TypeAdapter
from pydantic import ValidationError as PydanticValidationError

from ltobackup.shares import (
    ShareConfig,
    ShareValidationError,
    normalize_share_id,
)

_STORE_VERSION = 2
_MAX_RECORD_BYTES = 16_384
_SHARE_ADAPTER = TypeAdapter(ShareConfig)
_CREDENTIAL_FILE = re.compile(
    r"^(?P<share>[a-z0-9][a-z0-9-]{0,62})\.g(?P<generation>[1-9][0-9]*)\.credentials$"
)
_CREDENTIAL_TEMP_FILE = re.compile(
    r"^\.(?P<share>[a-z0-9][a-z0-9-]{0,62})\.g(?P<generation>[1-9][0-9]*)"
    r"\.credentials\.[0-9a-f]{24}\.tmp$"
)


class CredentialStoreError(RuntimeError):
    """A redacted credential-store failure."""

    def __init__(self) -> None:
        super().__init__("share credential store unavailable")


class CredentialConflict(CredentialStoreError):
    """The requested credential generation is stale or conflicts."""


@dataclass(frozen=True)
class CredentialStorePolicy:
    uid: int = 0
    gid: int = 0
    directory_mode: int = 0o700
    file_mode: int = 0o600

    def __post_init__(self) -> None:
        if (
            type(self.uid) is not int
            or type(self.gid) is not int
            or not 0 <= self.uid < 1 << 32
            or not 0 <= self.gid < 1 << 32
            or self.directory_mode != 0o700
            or self.file_mode != 0o600
        ):
            raise ValueError("invalid credential-store ownership policy")


@dataclass(frozen=True)
class CredentialState:
    share_id: str
    generation: int
    configured: bool


@dataclass(frozen=True)
class MountBinding:
    share_id: str
    config: ShareConfig
    config_revision: int
    credential_generation: int
    mounted: bool
    mount_identity_sha256: str | None


class CredentialStore:
    """Root-owned generation store for mount.cifs credential records."""

    def __init__(
        self,
        state_root: Path,
        *,
        credential_root: Path | None = None,
        request_key: bytes,
        policy: CredentialStorePolicy | None = None,
    ) -> None:
        self.state_root = Path(state_root)
        self.credential_root = Path(
            state_root if credential_root is None else credential_root
        )
        # Compatibility alias for callers that used the original single-root
        # store only to resolve the broker-internal credential path.
        self.root = self.credential_root
        self.policy = policy or CredentialStorePolicy()
        if (
            not self.state_root.is_absolute()
            or not self.credential_root.is_absolute()
            or type(request_key) is not bytes
            or len(request_key) != 32
        ):
            raise CredentialStoreError
        self._request_key = bytes(request_key)
        state_fd, credential_fd = self._open_roots()
        try:
            self._recover_all(state_fd, credential_fd)
        except (OSError, ValueError, TypeError):
            raise CredentialStoreError from None
        finally:
            os.close(credential_fd)
            os.close(state_fd)

    def install(
        self,
        share_id: str,
        generation: int,
        *,
        username: str,
        domain: str | None,
        password: str,
    ) -> CredentialState:
        share_id = _share_id(share_id)
        generation = _generation(generation)
        username = _field(username, maximum=256, empty=False)
        domain = _field(domain, maximum=256, empty=True)
        password = _field(password, maximum=4096, empty=False)
        request_digest = self._request_digest(
            share_id, generation, username, domain, password
        )
        credential_payload = _render_credential(username, domain, password)
        state_fd, credential_fd = self._open_roots()
        new_name = _credential_name(share_id, generation)
        published = False
        created = False
        state_publish_attempted = False
        try:
            current = self._recover_credential_state(
                state_fd, share_id, credential_fd=credential_fd
            )
            if current is not None and generation == current["generation"]:
                if current["configured"] and hmac.compare_digest(
                    current["request_hmac"], request_digest
                ):
                    self._validate_file(credential_fd, new_name)
                    os.fsync(credential_fd)
                    published = True
                    return CredentialState(share_id, generation, True)
                raise CredentialConflict
            expected = 1 if current is None else current["generation"] + 1
            if generation != expected:
                raise CredentialConflict
            self._atomic_write(credential_fd, new_name, credential_payload)
            created = True
            state = {
                "version": _STORE_VERSION,
                "share_id": share_id,
                "generation": generation,
                "configured": True,
                "request_hmac": request_digest,
                "cleanup_generations": (
                    [current["generation"]]
                    if current is not None and current["configured"]
                    else []
                ),
            }
            state_publish_attempted = True
            self._atomic_write(state_fd, _state_name(share_id), _canonical_state(state))
            published = True
            self._recover_cleanup_call(state_fd, credential_fd, state)
            return CredentialState(share_id, generation, True)
        except CredentialConflict:
            raise
        except (OSError, ValueError, TypeError):
            if created and not published and state_publish_attempted:
                try:
                    current = self._read_state(state_fd, share_id)
                    if (
                        current is not None
                        and current["configured"]
                        and current["generation"] == generation
                        and hmac.compare_digest(current["request_hmac"], request_digest)
                    ):
                        self._validate_file(credential_fd, new_name)
                        published = True
                        os.fsync(state_fd)
                        self._recover_cleanup_call(state_fd, credential_fd, current)
                        return CredentialState(share_id, generation, True)
                except (OSError, ValueError, TypeError):
                    if published:
                        raise CredentialStoreError from None
            raise CredentialStoreError from None
        finally:
            if created and not published and not state_publish_attempted:
                with contextlib.suppress(OSError):
                    os.unlink(new_name, dir_fd=credential_fd)
            os.close(credential_fd)
            os.close(state_fd)

    def delete(self, share_id: str, generation: int) -> CredentialState:
        share_id = _share_id(share_id)
        generation = _generation(generation)
        state_fd, credential_fd = self._open_roots()
        try:
            current = self._recover_credential_state(
                state_fd, share_id, credential_fd=credential_fd
            )
            if current is None or current["generation"] != generation:
                raise CredentialConflict
            if not current["configured"]:
                return CredentialState(share_id, generation, False)
            state = {
                **current,
                "configured": False,
                "request_hmac": "0" * 64,
                "cleanup_generations": [generation],
            }
            self._atomic_write(state_fd, _state_name(share_id), _canonical_state(state))
            self._recover_cleanup_call(state_fd, credential_fd, state)
            return CredentialState(share_id, generation, False)
        except CredentialConflict:
            raise
        except (OSError, ValueError, TypeError):
            raise CredentialStoreError from None
        finally:
            os.close(credential_fd)
            os.close(state_fd)

    def state(self, share_id: str) -> CredentialState | None:
        share_id = _share_id(share_id)
        state_fd, credential_fd = self._open_roots()
        try:
            state = self._recover_credential_state(
                state_fd, share_id, credential_fd=credential_fd
            )
            if state is None:
                return None
            if state["configured"]:
                self._validate_file(
                    credential_fd,
                    _credential_name(share_id, state["generation"]),
                )
            return CredentialState(share_id, state["generation"], state["configured"])
        except (OSError, ValueError, TypeError):
            raise CredentialStoreError from None
        finally:
            os.close(credential_fd)
            os.close(state_fd)

    def credential_path(self, share_id: str, generation: int) -> Path:
        """Return the internal broker-only helper path after exact validation."""

        share_id = _share_id(share_id)
        generation = _generation(generation)
        state_fd, credential_fd = self._open_roots()
        try:
            state = self._recover_credential_state(
                state_fd, share_id, credential_fd=credential_fd
            )
            if (
                state is None
                or not state["configured"]
                or state["generation"] != generation
            ):
                raise CredentialConflict
            name = _credential_name(share_id, generation)
            self._validate_file(credential_fd, name)
            return self.credential_root / name
        finally:
            os.close(credential_fd)
            os.close(state_fd)

    def record_mount(
        self,
        share_id: str,
        config: ShareConfig,
        *,
        config_revision: int,
        credential_generation: int,
        mount_identity_sha256: str,
    ) -> MountBinding:
        share_id = _share_id(share_id)
        config = _config(config)
        config_revision = _positive_revision(config_revision)
        credential_generation = _nonnegative_generation(credential_generation)
        mount_identity_sha256 = _digest(mount_identity_sha256)
        directory_fd = self._open_directory(self.state_root)
        try:
            existing = self._read_mount_state(directory_fd, share_id)
            candidate = MountBinding(
                share_id,
                config,
                config_revision,
                credential_generation,
                True,
                mount_identity_sha256,
            )
            if existing is not None:
                if (
                    config_revision < existing.config_revision
                    or credential_generation < existing.credential_generation
                    or (
                        config_revision == existing.config_revision
                        and (
                            config != existing.config
                            or credential_generation != existing.credential_generation
                        )
                    )
                ):
                    raise CredentialConflict
                if existing.mounted:
                    if existing != candidate:
                        raise CredentialConflict
                    return existing
            self._atomic_write(
                directory_fd,
                _mount_state_name(share_id),
                _canonical_state(_mount_binding_mapping(candidate)),
            )
            return candidate
        except CredentialConflict:
            raise
        except (OSError, ValueError, TypeError, PydanticValidationError):
            raise CredentialStoreError from None
        finally:
            os.close(directory_fd)

    def mount_binding(self, share_id: str) -> MountBinding | None:
        share_id = _share_id(share_id)
        directory_fd = self._open_directory(self.state_root)
        try:
            return self._read_mount_state(directory_fd, share_id)
        except (OSError, ValueError, TypeError, PydanticValidationError):
            raise CredentialStoreError from None
        finally:
            os.close(directory_fd)

    def mount_bindings(self) -> tuple[MountBinding, ...]:
        """Return one validated, deterministic snapshot of durable mount bindings."""

        directory_fd = self._open_directory(self.state_root)
        try:
            bindings: list[MountBinding] = []
            suffix = ".mount-state"
            for name in sorted(os.listdir(directory_fd)):
                if type(name) is not str or not name.endswith(suffix):
                    continue
                candidate = name[: -len(suffix)]
                share_id = _share_id(candidate)
                if share_id != candidate:
                    raise CredentialStoreError
                binding = self._read_mount_state(directory_fd, share_id)
                if binding is None:
                    raise CredentialStoreError
                bindings.append(binding)
            return tuple(bindings)
        except CredentialStoreError:
            raise
        except (OSError, ValueError, TypeError, PydanticValidationError):
            raise CredentialStoreError from None
        finally:
            os.close(directory_fd)

    def mark_unmounted(
        self, share_id: str, *, expected_mount_identity_sha256: str
    ) -> MountBinding:
        share_id = _share_id(share_id)
        expected_mount_identity_sha256 = _digest(expected_mount_identity_sha256)
        directory_fd = self._open_directory(self.state_root)
        try:
            current = self._read_mount_state(directory_fd, share_id)
            if (
                current is None
                or not current.mounted
                or current.mount_identity_sha256 != expected_mount_identity_sha256
            ):
                raise CredentialConflict
            updated = MountBinding(
                current.share_id,
                current.config,
                current.config_revision,
                current.credential_generation,
                False,
                None,
            )
            self._atomic_write(
                directory_fd,
                _mount_state_name(share_id),
                _canonical_state(_mount_binding_mapping(updated)),
            )
            return updated
        except CredentialConflict:
            raise
        except (OSError, ValueError, TypeError, PydanticValidationError):
            raise CredentialStoreError from None
        finally:
            os.close(directory_fd)

    def _request_digest(
        self,
        share_id: str,
        generation: int,
        username: str,
        domain: str | None,
        password: str,
    ) -> str:
        canonical = json.dumps(
            {
                "domain": domain,
                "generation": generation,
                "password": password,
                "share_id": share_id,
                "username": username,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hmac.new(
            self._request_key,
            b"lto-share-credential-request-v1\0" + canonical,
            hashlib.sha256,
        ).hexdigest()

    def _open_directory(self, root: Path) -> int:
        try:
            fd = os.open(
                root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            status = os.fstat(fd)
            if (
                not stat.S_ISDIR(status.st_mode)
                or status.st_uid != self.policy.uid
                or status.st_gid != self.policy.gid
                or stat.S_IMODE(status.st_mode) != self.policy.directory_mode
            ):
                raise CredentialStoreError
            return fd
        except CredentialStoreError:
            with contextlib.suppress(UnboundLocalError, OSError):
                os.close(fd)
            raise
        except OSError:
            raise CredentialStoreError from None

    def _open_roots(self) -> tuple[int, int]:
        state_fd = self._open_directory(self.state_root)
        try:
            credential_fd = self._open_directory(self.credential_root)
        except BaseException:
            os.close(state_fd)
            raise
        return state_fd, credential_fd

    def _read_state(self, directory_fd: int, share_id: str) -> dict[str, object] | None:
        try:
            raw = self._read_file(directory_fd, _state_name(share_id))
        except FileNotFoundError:
            return None
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise CredentialStoreError from None
        legacy_keys = {
            "version",
            "share_id",
            "generation",
            "configured",
            "request_hmac",
        }
        current_keys = legacy_keys | {"cleanup_generations"}
        keys = frozenset(value) if type(value) is dict else frozenset()
        if (
            type(value) is not dict
            or not (
                keys == frozenset(legacy_keys)
                and value.get("version") == 1
                or keys == frozenset(current_keys)
                and value.get("version") == _STORE_VERSION
            )
            or _canonical_state(value) != raw
            or value["share_id"] != share_id
            or type(value["generation"]) is not int
            or value["generation"] < 1
            or type(value["configured"]) is not bool
            or not _is_digest(value["request_hmac"])
        ):
            raise CredentialStoreError
        cleanup = value.get("cleanup_generations", [])
        if (
            type(cleanup) is not list
            or any(type(item) is not int or item < 1 for item in cleanup)
            or cleanup != sorted(set(cleanup))
        ):
            raise CredentialStoreError
        value = {**value, "version": _STORE_VERSION, "cleanup_generations": cleanup}
        return value

    def _recover_all(self, state_fd: int, credential_fd: int) -> None:
        authoritative: set[str] = set()
        for name in os.listdir(state_fd):
            if type(name) is not str or not name.endswith(".state"):
                continue
            candidate = name[: -len(".state")]
            try:
                share_id = normalize_share_id(candidate)
            except (ShareValidationError, TypeError):
                raise CredentialStoreError from None
            if share_id != candidate:
                raise CredentialStoreError
            state = self._read_state(state_fd, share_id)
            if state is None:
                raise CredentialStoreError
            state = self._recover_cleanup_call(state_fd, credential_fd, state)
            if state["configured"]:
                credential_name = _credential_name(share_id, state["generation"])
                self._validate_file(credential_fd, credential_name)
                authoritative.add(credential_name)
        for name in os.listdir(credential_fd):
            if type(name) is not str:
                continue
            final_match = _CREDENTIAL_FILE.fullmatch(name)
            temporary_match = _CREDENTIAL_TEMP_FILE.fullmatch(name)
            if temporary_match is not None:
                self._unlink_missing_ok(credential_fd, name)
                continue
            if final_match is None or name in authoritative:
                continue
            self._unlink_missing_ok(credential_fd, name)

    def _recover_credential_state(
        self,
        state_fd: int,
        share_id: str,
        *,
        credential_fd: int | None = None,
    ) -> dict[str, object] | None:
        state = self._read_state(state_fd, share_id)
        if state is None:
            return None
        return self._recover_cleanup_call(
            state_fd,
            state_fd if credential_fd is None else credential_fd,
            state,
        )

    def _recover_cleanup_call(
        self,
        state_fd: int,
        credential_fd: int,
        state: dict[str, object],
    ) -> dict[str, object]:
        if self.state_root == self.credential_root:
            return self._recover_cleanup_with_retry(state_fd, state)
        return self._recover_cleanup_with_retry(
            state_fd, state, credential_fd=credential_fd
        )

    def _recover_cleanup_with_retry(
        self,
        state_fd: int,
        state: dict[str, object],
        *,
        credential_fd: int | None = None,
    ) -> dict[str, object]:
        credential_fd = state_fd if credential_fd is None else credential_fd
        try:
            return self._recover_cleanup(state_fd, credential_fd, state)
        except OSError:
            return self._recover_cleanup(state_fd, credential_fd, state)

    def _recover_cleanup(
        self,
        state_fd: int,
        credential_fd: int,
        state: dict[str, object],
    ) -> dict[str, object]:
        cleanup = state["cleanup_generations"]
        if not cleanup:
            return state
        for generation in cleanup:
            self._unlink_missing_ok(
                credential_fd, _credential_name(state["share_id"], generation)
            )
        recovered = {**state, "cleanup_generations": []}
        self._atomic_write(
            state_fd,
            _state_name(state["share_id"]),
            _canonical_state(recovered),
        )
        return recovered

    def _read_mount_state(
        self, directory_fd: int, share_id: str
    ) -> MountBinding | None:
        try:
            raw = self._read_file(directory_fd, _mount_state_name(share_id))
        except FileNotFoundError:
            return None
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise CredentialStoreError from None
        if (
            type(value) is not dict
            or frozenset(value)
            != {
                "version",
                "share_id",
                "config",
                "config_revision",
                "credential_generation",
                "mounted",
                "mount_identity_sha256",
            }
            or _canonical_state(value) != raw
            or value["version"] != 1
            or value["share_id"] != share_id
            or type(value["mounted"]) is not bool
        ):
            raise CredentialStoreError
        identity = value["mount_identity_sha256"]
        if identity is not None:
            identity = _digest(identity)
        if value["mounted"] != (identity is not None):
            raise CredentialStoreError
        return MountBinding(
            share_id,
            _config(value["config"]),
            _positive_revision(value["config_revision"]),
            _nonnegative_generation(value["credential_generation"]),
            value["mounted"],
            identity,
        )

    def _read_file(self, directory_fd: int, name: str) -> bytes:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        try:
            self._validate_status(os.fstat(fd))
            chunks = []
            remaining = _MAX_RECORD_BYTES + 1
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            if not payload or len(payload) > _MAX_RECORD_BYTES:
                raise CredentialStoreError
            return payload
        finally:
            os.close(fd)

    def _validate_file(self, directory_fd: int, name: str) -> None:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        try:
            self._validate_status(os.fstat(fd))
        finally:
            os.close(fd)

    def _validate_status(self, status: os.stat_result) -> None:
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != self.policy.uid
            or status.st_gid != self.policy.gid
            or stat.S_IMODE(status.st_mode) != self.policy.file_mode
            or status.st_nlink != 1
        ):
            raise CredentialStoreError

    def _atomic_write(self, directory_fd: int, target: str, payload: bytes) -> None:
        temporary = f".{target}.{secrets.token_hex(12)}.tmp"
        fd: int | None = None
        try:
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                self.policy.file_mode,
                dir_fd=directory_fd,
            )
            offset = 0
            while offset < len(payload):
                written = os.write(fd, payload[offset:])
                if written <= 0:
                    raise OSError
                offset += written
            os.fsync(fd)
            self._validate_status(os.fstat(fd))
            os.close(fd)
            fd = None
            os.replace(
                temporary,
                target,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
        finally:
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)
            with contextlib.suppress(OSError):
                os.unlink(temporary, dir_fd=directory_fd)

    @staticmethod
    def _unlink(directory_fd: int, name: str) -> None:
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)

    def _unlink_missing_ok(self, directory_fd: int, name: str) -> None:
        try:
            self._unlink(directory_fd, name)
        except FileNotFoundError:
            os.fsync(directory_fd)


def _share_id(value: str) -> str:
    try:
        return normalize_share_id(value)
    except (ShareValidationError, TypeError):
        raise CredentialStoreError from None


def _generation(value: int) -> int:
    if type(value) is not int or not 1 <= value < 1 << 63:
        raise CredentialConflict
    return value


def _field(value: str | None, *, maximum: int, empty: bool) -> str | None:
    if value is None and empty:
        return None
    if type(value) is not str or len(value) > maximum or (not value and not empty):
        raise CredentialStoreError
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise CredentialStoreError
    return value or None


def _render_credential(username: str, domain: str | None, password: str) -> bytes:
    lines = [f"username={username}"]
    if domain is not None:
        lines.append(f"domain={domain}")
    lines.append(f"password={password}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _state_name(share_id: str) -> str:
    return f"{share_id}.state"


def _credential_name(share_id: str, generation: int) -> str:
    return f"{share_id}.g{generation}.credentials"


def _mount_state_name(share_id: str) -> str:
    return f"{share_id}.mount-state"


def _mount_binding_mapping(binding: MountBinding) -> dict[str, object]:
    return {
        "version": 1,
        "share_id": binding.share_id,
        "config": binding.config.model_dump(mode="json"),
        "config_revision": binding.config_revision,
        "credential_generation": binding.credential_generation,
        "mounted": binding.mounted,
        "mount_identity_sha256": binding.mount_identity_sha256,
    }


def _config(value: object) -> ShareConfig:
    try:
        return _SHARE_ADAPTER.validate_python(value)
    except (PydanticValidationError, TypeError, ValueError):
        raise CredentialStoreError from None


def _positive_revision(value: object) -> int:
    if type(value) is not int or not 1 <= value < 1 << 63:
        raise CredentialStoreError
    return value


def _nonnegative_generation(value: object) -> int:
    if type(value) is not int or not 0 <= value < 1 << 63:
        raise CredentialStoreError
    return value


def _digest(value: object) -> str:
    if not _is_digest(value):
        raise CredentialStoreError
    return value


def _canonical_state(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise CredentialStoreError from None


def _is_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
