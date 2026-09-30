from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from .errors import ValidationError
from .media import require_ltfs_profile

LTO6_LTFS_DATA_BYTES = 2_410_000_000_000
LEGACY_DEFAULT_RESERVE_BYTES = 200 * 1024**3
DEFAULT_RESERVE_BYTES = 0
LEGACY_LTO6_NATIVE_BYTES = 2_500_000_000_000
MAX_MIN_AGE_SECONDS = 31 * 24 * 60 * 60


def default_state_dir() -> Path:
    return Path.home() / ".local" / "state" / "lto-backup-manager"


@dataclass(frozen=True)
class Settings:
    reserve_bytes: int = DEFAULT_RESERVE_BYTES
    tape_capacity_bytes: int = LTO6_LTFS_DATA_BYTES
    buffer_bytes: int = 16 * 1024**2
    min_age_seconds: int = 900
    tape_root_directory: str = ".lto-backup"
    catalog_backup_directory: str = ""
    verify_unchanged_content: bool = False
    default_media_key: str = "LTO-6"

    def validate(self) -> None:
        if self.reserve_bytes < 0:
            raise ValidationError("The application margin cannot be negative")
        profile = require_ltfs_profile(self.default_media_key)
        if profile.ltfs_usable_bytes is None or profile.ltfs_usable_bytes <= self.reserve_bytes:
            raise ValidationError("La capacita dati LTFS deve superare il margine applicativo")
        if not 1024**2 <= self.buffer_bytes <= 64 * 1024**2:
            raise ValidationError("Il buffer deve essere compreso tra 1 e 64 MiB")
        if not 0 <= self.min_age_seconds <= MAX_MIN_AGE_SECONDS:
            raise ValidationError("min_age_seconds deve essere compreso tra 0 e 31 giorni")
        if (
            not self.tape_root_directory
            or self.tape_root_directory in {".", ".."}
            or "/" in self.tape_root_directory
            or "\\" in self.tape_root_directory
            or any(ord(character) < 32 or ord(character) == 127 for character in self.tape_root_directory)
        ):
            raise ValidationError("tape_root_directory deve essere un singolo nome di cartella")
        if self.catalog_backup_directory and not Path(self.catalog_backup_directory).is_absolute():
            raise ValidationError("catalog_backup_directory deve essere un percorso assoluto o UNC")
        if not isinstance(self.verify_unchanged_content, bool):
            raise ValidationError("verify_unchanged_content deve essere true oppure false")


@dataclass(frozen=True)
class AppPaths:
    state_dir: Path

    @property
    def config_file(self) -> Path:
        return self.state_dir / "config.json"

    @property
    def catalog_file(self) -> Path:
        return self.state_dir / "catalog.db"

    @property
    def log_dir(self) -> Path:
        return self.state_dir / "logs"

    @property
    def temp_dir(self) -> Path:
        return self.state_dir / "temp"

    @property
    def lock_file(self) -> Path:
        return self.state_dir / "run.lock"

    def catalog_backup_file(self, configured_directory: str = "") -> Path:
        directory = (
            Path(configured_directory)
            if configured_directory
            else self.state_dir / "backups" / "catalog"
        )
        return directory / "catalog-latest.db"

    def create(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)


def save_settings(paths: AppPaths, settings: Settings) -> None:
    settings.validate()
    paths.create()
    temporary = paths.config_file.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(asdict(settings), indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, paths.config_file)


def _read_settings(paths: AppPaths) -> tuple[dict, Settings]:
    if not paths.config_file.exists():
        raise ValidationError(f"Configurazione non inizializzata: eseguire init ({paths.config_file})")
    try:
        raw = json.loads(paths.config_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(
            f"Impossibile leggere la configurazione {paths.config_file}: {exc}"
        ) from exc
    if not isinstance(raw, dict):
        raise ValidationError(
            f"Configurazione non valida in {paths.config_file}: atteso un oggetto JSON"
        )
    try:
        settings = Settings(**raw)
        settings.validate()
    except ValidationError:
        raise
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValidationError(
            f"Configurazione non valida in {paths.config_file}: {exc}"
        ) from exc
    return raw, settings


def load_settings(paths: AppPaths) -> Settings:
    _, settings = _read_settings(paths)
    return settings


def upgrade_legacy_settings(paths: AppPaths) -> Settings:
    """Replace only the former built-in LTO-6 capacity assumptions."""

    raw, settings = _read_settings(paths)
    try:
        legacy_capacity = (
            "tape_capacity_bytes" not in raw
            or int(raw["tape_capacity_bytes"]) == LEGACY_LTO6_NATIVE_BYTES
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            f"Configurazione non valida in {paths.config_file}: tape_capacity_bytes"
        ) from exc
    updated = settings
    if legacy_capacity:
        updated = replace(updated, tape_capacity_bytes=LTO6_LTFS_DATA_BYTES)
    # Versioni precedenti applicavano 200 GiB a ogni cassetta. Ora il piano usa
    # l'intera partizione dati LTFS e la copia usa lo spazio libero del volume.
    if settings.reserve_bytes == LEGACY_DEFAULT_RESERVE_BYTES:
        updated = replace(updated, reserve_bytes=DEFAULT_RESERVE_BYTES)
    updated.validate()
    if updated != settings or "tape_capacity_bytes" not in raw:
        save_settings(paths, updated)
    return updated
