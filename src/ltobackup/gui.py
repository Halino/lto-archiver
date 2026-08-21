from __future__ import annotations

import argparse
import math
import os
import queue
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from tkinter import filedialog, messagebox, simpledialog
import tkinter as tk
from tkinter import ttk
from typing import Callable, TextIO

from . import __version__
from .application import LtoApplication
from .errors import LtoBackupError, ValidationError
from .filemeta import describe_windows_attributes
from .i18n import LANGUAGES, Translator, load_language, save_language
from .media import get_lto_media_profile, lto_media_profiles
from .security import ensure_controlled_folder_access
from .settings import default_state_dir
from .util import LTFS_SLOW_CLOSE_SECONDS, human_bytes


@dataclass(frozen=True)
class ProgressView:
    percent: float
    message: str


@dataclass(frozen=True)
class NavigationItem:
    key: str
    label: str
    title: str
    subtitle: str
    marker: str = ""


NAVIGATION_ITEMS = (
    NavigationItem("overview", "Panoramica", "Centro operativo", "Stato dell'archivio e ultime attivita"),
    NavigationItem("libraries", "Librerie", "Librerie sorgente", "Collega e controlla le cartelle SMB", "01"),
    NavigationItem("inventory", "Piano cassette", "Piano del job", "Distribuisci insieme le librerie del job sulle cassette", "02"),
    NavigationItem(
        "automatic", "Job automatici", "Job salvati e ripartenza",
        "Salva il piano, poi avvia esplicitamente il job selezionato", "03",
    ),
    NavigationItem("backup", "Backup manuale", "Backup manuale su LTFS", "Verifica una cassetta gia montata e scrivi un lotto"),
    NavigationItem("restore", "Ripristina", "Ripristino libreria", "Trova le cassette richieste e recupera i file", "04"),
    NavigationItem("search", "Esplora backup", "Esplora backup offline", "Naviga cartelle, cerca file e consulta i metadati senza cassette"),
    NavigationItem("catalog", "Catalogo", "Catalogo e cassette", "Controlla integrita, nastri e blocchi"),
)


def _decimal_tb(value: float) -> str:
    return f"{value:g} TB"


def lto_capacity_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for profile in lto_media_profiles():
        rows.append(
            {
                "media_key": profile.key,
                "native": _decimal_tb(profile.native_capacity_tb),
                "ltfs": (
                    _decimal_tb(profile.ltfs_usable_tb)
                    if profile.ltfs_usable_tb is not None
                    else "Non supportato"
                ),
                "compressed": _decimal_tb(profile.compressed_capacity_tb),
                "barcode_suffix": profile.barcode_suffix,
                "notes": (
                    "Solo riferimento: LTFS richiede LTO-5+"
                    if not profile.ltfs_supported
                    else ("Standard" if profile.variant == "standard" else
                          "Premium" if profile.variant == "premium" else "Riscrivibile LTFS")
                ),
            }
        )
    return rows


def fitted_window_size(screen_width: int, screen_height: int) -> tuple[int, int]:
    """Keep the initial window inside the usable area of smaller displays."""

    return min(1360, max(1, screen_width - 32)), min(840, max(1, screen_height - 80))


def responsive_mode(window_width: int) -> str:
    # The automatic-job workspace contains two information-dense panels.  A
    # 1366px display does not leave enough usable width after the sidebar and
    # workspace padding, so keep the vertical layout until a true wide screen.
    return "compact" if window_width < 1550 else "wide"


def stable_status_field(
    parent: tk.Misc,
    variable: tk.StringVar,
    *,
    height: int,
    background: str,
    foreground: str,
    font: tuple | None = None,
    wraplength: int = 0,
) -> tk.Frame:
    """Keep live phase text from changing the requested panel geometry."""

    field = tk.Frame(
        parent,
        width=1,
        height=max(1, height),
        background=background,
        highlightthickness=0,
        borderwidth=0,
    )
    field.pack_propagate(False)
    label = tk.Label(
        field,
        textvariable=variable,
        background=background,
        foreground=foreground,
        anchor="nw",
        justify="left",
        width=1,
        font=font,
        wraplength=max(0, wraplength),
    )
    label.pack(fill="both", expand=True)
    return field


def stable_metric_cell(
    parent: tk.Misc,
    label_text: str,
    variable: tk.StringVar,
    *,
    background: str,
    foreground: str = "#ffffff",
    accent: str = "#4fd1c5",
    height: int = 64,
) -> tk.Frame:
    """Render a live metric without letting its text resize surrounding panels."""

    cell = tk.Frame(
        parent,
        width=1,
        height=max(1, height),
        bg=background,
        padx=10,
        pady=8,
        highlightthickness=0,
        borderwidth=0,
    )
    cell.pack_propagate(False)
    tk.Label(
        cell,
        text=label_text,
        bg=background,
        fg=accent,
        font=("Cascadia Mono SemiBold", 8),
        anchor="w",
        width=1,
    ).pack(fill="x")
    tk.Label(
        cell,
        textvariable=variable,
        bg=background,
        fg=foreground,
        font=("Cascadia Mono SemiBold", 12),
        anchor="w",
        width=1,
    ).pack(fill="x", pady=(3, 0))
    return cell


def write_speed_text(
    write_bps: float | None,
    average_write_bps: float,
    *,
    stalled_seconds: int | None = None,
    language: str = "it",
) -> str:
    labels = {
        "it": ("Media effettiva cassetta", "Invio alla cache LTFS", "nessuna conferma dalla cache da", "in attesa di conferma LTFS"),
        "en": ("Effective tape average", "LTFS cache admission", "no cache confirmation for", "awaiting LTFS confirmation"),
        "fr": ("Moyenne effective cassette", "Envoi au cache LTFS", "aucune confirmation du cache depuis", "en attente de confirmation LTFS"),
        "de": ("Effektiver Bandmittelwert", "LTFS-Cache-Ubergabe", "keine Cache-Bestatigung seit", "wartet auf LTFS-Bestatigung"),
        "es": ("Media efectiva del cartucho", "Envio a la cache LTFS", "sin confirmacion de cache desde", "esperando confirmacion LTFS"),
    }.get(
        language,
        ("Media effettiva cassetta", "Invio alla cache LTFS", "nessuna conferma dalla cache da", "in attesa di conferma LTFS"),
    )
    current = labels[3] if write_bps is None else f"{human_bytes(max(0, int(write_bps)))}/s"
    text = (
        f"{labels[0]}: {human_bytes(max(0, int(average_write_bps)))}/s"
        f"  |  {labels[1]}: {current}"
    )
    if stalled_seconds is not None:
        text += f"  |  {labels[2]} {max(0, stalled_seconds)}s"
    return text


def smooth_live_write_bps(
    previous_bps: float | None,
    sample_bps: float | None,
    *,
    alpha: float = 0.25,
) -> float | None:
    """Stabilize the cache-admission rate without inventing missing samples."""

    if sample_bps is None or sample_bps <= 0:
        return previous_bps
    if previous_bps is None or previous_bps <= 0:
        return float(sample_bps)
    weight = min(1.0, max(0.0, float(alpha)))
    return ((1.0 - weight) * float(previous_bps)) + (weight * float(sample_bps))


def _adaptive_rate_ceiling(rates: list[float], default: float) -> float:
    positive = [float(rate) for rate in rates if float(rate) > 0.0]
    if not positive:
        return float(default)
    target = max(1_000_000.0, max(positive) * 1.1)
    magnitude = 10.0 ** math.floor(math.log10(target))
    for multiplier in (1.0, 2.0, 5.0, 10.0):
        candidate = magnitude * multiplier
        if candidate >= target:
            return candidate
    return magnitude * 10.0


def write_speed_chart_axes(
    samples: list[tuple[float, float, float | None]],
) -> dict[str, float]:
    """Return independent readable scales for effective and LTFS-cache rates."""

    default = WriteSpeedChart.DEFAULT_CEILING_BPS
    return {
        "effective": _adaptive_rate_ceiling([row[1] for row in samples], default),
        "cache": _adaptive_rate_ceiling(
            [row[2] for row in samples if row[2] is not None], default
        ),
    }


def write_speed_chart_ticks(
    effective_ceiling_bps: float,
    cache_ceiling_bps: float,
) -> dict[str, tuple[str, str, str]]:
    """Label the top, midpoint, and origin of both independent rate axes."""

    def labels(ceiling_bps: float) -> tuple[str, str, str]:
        ceiling = max(0, int(ceiling_bps))
        return (
            f"{human_bytes(ceiling)}/s",
            f"{human_bytes(ceiling // 2)}/s",
            f"{human_bytes(0)}/s",
        )

    return {
        "effective": labels(effective_ceiling_bps),
        "cache": labels(cache_ceiling_bps),
    }


def write_speed_chart_geometry(width: int) -> dict[str, int | bool]:
    """Keep every plot coordinate inside the actual canvas width."""

    actual = max(120, int(width))
    axis_margin = (
        76 if actual >= 360 else 64 if actual >= 220 else max(46, actual // 3)
    )
    left = axis_margin
    right = max(left + 20, actual - axis_margin)
    return {
        "width": actual,
        "left": left,
        "right": right,
        "compact": actual < 360,
    }


def append_regular_write_speed_sample(
    samples: list[tuple[float, float, float | None]],
    timestamp: float,
    effective_bps: float,
    cache_bps: float | None,
    *,
    interval_seconds: float = 1.0,
    horizon_seconds: float = 300.0,
) -> list[tuple[float, float, float | None]]:
    """Place the latest reading in a fixed time bucket without inventing gaps."""

    interval = max(0.1, float(interval_seconds))
    observed_at = float(timestamp)
    bucket = math.floor(observed_at / interval) * interval
    sample = (
        bucket,
        max(0.0, float(effective_bps)),
        None if cache_bps is None else max(0.0, float(cache_bps)),
    )
    updated = list(samples)
    if updated and updated[-1][0] == bucket:
        updated[-1] = sample
    elif not updated or bucket > updated[-1][0]:
        updated.append(sample)
    else:
        by_bucket = {row[0]: row for row in updated}
        by_bucket[bucket] = sample
        updated = [by_bucket[key] for key in sorted(by_bucket)]
    cutoff = bucket - max(interval, float(horizon_seconds))
    return [row for row in updated if row[0] >= cutoff]


def stabilize_rate_ceiling(
    previous: float,
    requested: float,
    elapsed_seconds: float,
) -> float:
    """Raise an axis immediately and lower it gradually to avoid visual jumps."""

    prior = max(1.0, float(previous))
    target = max(1.0, float(requested))
    if target >= prior:
        return target
    decay = 0.8 ** (max(0.0, float(elapsed_seconds)) / 60.0)
    return max(target, prior * decay)


class WriteSpeedChart(tk.Canvas):
    """Fixed-height tape transport trace built with Tk only."""

    HORIZON_SECONDS = 300.0
    DEFAULT_CEILING_BPS = 200_000_000.0

    def __init__(self, master, *, language: str = "it") -> None:
        super().__init__(
            master,
            height=112,
            background="#142435",
            highlightthickness=0,
            borderwidth=0,
        )
        self.language = language
        self._samples: list[tuple[float, float, float | None]] = []
        self._ceiling_bps = self.DEFAULT_CEILING_BPS
        self._effective_ceiling_bps = self.DEFAULT_CEILING_BPS
        self._cache_ceiling_bps = self.DEFAULT_CEILING_BPS
        self._last_axis_update_at: float | None = None
        self._last_sample_at: float | None = None
        self.bind("<Configure>", lambda _event: self.render())

    def reset(self) -> None:
        self._samples.clear()
        self._ceiling_bps = self.DEFAULT_CEILING_BPS
        self._effective_ceiling_bps = self.DEFAULT_CEILING_BPS
        self._cache_ceiling_bps = self.DEFAULT_CEILING_BPS
        self._last_axis_update_at = None
        self._last_sample_at = None
        self.render()

    def add_sample(
        self,
        timestamp: float,
        effective_bps: float,
        cache_bps: float | None,
    ) -> None:
        self._samples = append_regular_write_speed_sample(
            self._samples,
            timestamp,
            effective_bps,
            cache_bps,
            horizon_seconds=self.HORIZON_SECONDS,
        )
        self._last_sample_at = float(timestamp)
        self.render(now=float(timestamp))

    def render(self, *, now: float | None = None) -> None:
        self.delete("all")
        geometry = write_speed_chart_geometry(
            self.winfo_width() or self.winfo_reqwidth()
        )
        width = int(geometry["width"])
        height = 112
        left = int(geometry["left"])
        right = int(geometry["right"])
        compact = bool(geometry["compact"])
        top, bottom = 25, 91
        now = time.monotonic() if now is None else float(now)
        axes = write_speed_chart_axes(self._samples)
        last_axis_at = getattr(self, "_last_axis_update_at", None)
        elapsed = 0.0 if last_axis_at is None else max(0.0, now - last_axis_at)
        previous_effective = getattr(
            self, "_effective_ceiling_bps", axes["effective"]
        )
        previous_cache = getattr(self, "_cache_ceiling_bps", axes["cache"])
        effective_ceiling = (
            axes["effective"]
            if last_axis_at is None
            else stabilize_rate_ceiling(previous_effective, axes["effective"], elapsed)
        )
        cache_ceiling = (
            axes["cache"]
            if last_axis_at is None
            else stabilize_rate_ceiling(previous_cache, axes["cache"], elapsed)
        )
        self._effective_ceiling_bps = effective_ceiling
        self._cache_ceiling_bps = cache_ceiling
        self._last_axis_update_at = now
        self._ceiling_bps = effective_ceiling
        labels = {
            "it": ("ANDAMENTO 5 MIN", "media cassetta", "cache LTFS", "5 min fa", "ora"),
            "en": ("5 MIN TREND", "tape average", "LTFS cache", "5 min ago", "now"),
            "fr": ("TENDANCE 5 MIN", "moyenne cassette", "cache LTFS", "il y a 5 min", "maintenant"),
            "de": ("5-MIN-VERLAUF", "Bandmittel", "LTFS-Cache", "vor 5 Min", "jetzt"),
            "es": ("TENDENCIA 5 MIN", "media cartucho", "cache LTFS", "hace 5 min", "ahora"),
        }.get(
            self.language,
            ("ANDAMENTO 5 MIN", "media cassetta", "cache LTFS", "5 min fa", "ora"),
        )
        self.create_text(
            8, 12, text="5 MIN" if compact else labels[0], anchor="w", fill="#91a2af",
            font=("Cascadia Mono SemiBold", 7),
        )
        if width >= 190:
            effective_legend = width - (142 if compact else 160)
            cache_legend = width - (67 if compact else 78)
            self.create_line(
                effective_legend, 12, effective_legend + 14, 12,
                fill="#5dd6c0", width=2,
            )
            self.create_text(
                effective_legend + 19, 12, text=labels[1], anchor="w", fill="#d9e2e7",
                font=("Cascadia Mono", 7),
            )
            self.create_line(
                cache_legend, 12, cache_legend + 14, 12,
                fill="#d8942f", width=2,
            )
            self.create_text(
                cache_legend + 19, 12, text=labels[2], anchor="w", fill="#d9e2e7",
                font=("Cascadia Mono", 7),
            )
        for index in range(3):
            y = top + ((bottom - top) * index / 2)
            self.create_line(left, y, right, y, fill="#2c4152", width=1)
        ticks = write_speed_chart_ticks(effective_ceiling, cache_ceiling)
        tick_font = ("Cascadia Mono", 6 if compact else 7)
        for index, y in enumerate(
            (top, top + ((bottom - top) / 2), bottom)
        ):
            self.create_text(
                left - 4,
                y,
                text=ticks["effective"][index],
                anchor="e",
                fill="#5dd6c0",
                font=tick_font,
            )
            self.create_text(
                right + 4,
                y,
                text=ticks["cache"][index],
                anchor="w",
                fill="#d8942f",
                font=tick_font,
            )
        self.create_text(
            left, height - 9, text=labels[3], anchor="w", fill="#60798b",
            font=("Cascadia Mono", 7),
        )
        self.create_text(
            right, height - 9, text=labels[4], anchor="e", fill="#60798b",
            font=("Cascadia Mono", 7),
        )

        def point(timestamp: float, rate: float, ceiling: float) -> tuple[float, float]:
            x = left + max(0.0, min(1.0, 1.0 - ((now - timestamp) / self.HORIZON_SECONDS))) * (right - left)
            y = bottom - min(1.0, rate / ceiling) * (bottom - top)
            return x, y

        effective = [point(row[0], row[1], effective_ceiling) for row in self._samples]
        cache_segments: list[list[tuple[float, float]]] = []
        current_segment: list[tuple[float, float]] = []
        for timestamp, _effective, cache in self._samples:
            if cache is None:
                if current_segment:
                    cache_segments.append(current_segment)
                    current_segment = []
                continue
            current_segment.append(point(timestamp, cache, cache_ceiling))
        if current_segment:
            cache_segments.append(current_segment)
        if len(effective) >= 2:
            self.create_line(*[coordinate for item in effective for coordinate in item], fill="#5dd6c0", width=2, smooth=False)
        for segment in cache_segments:
            if len(segment) >= 2:
                self.create_line(*[coordinate for item in segment for coordinate in item], fill="#d8942f", width=2, smooth=False)


def format_duration(seconds: float | int | None, *, language: str = "it") -> str:
    """Format an operator ETA without implying precision below one second."""

    if seconds is None:
        return "-"
    total = max(0, int(round(float(seconds))))
    days, remainder = divmod(total, 86_400)
    hours, remainder = divmod(remainder, 3_600)
    minutes, secs = divmod(remainder, 60)
    day_suffix = {"it": "g", "en": "d", "fr": "j", "de": "T", "es": "d"}.get(
        language, "g"
    )
    clock = f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{days}{day_suffix} {clock}" if days else clock


def finalization_view(event: dict, *, language: str = "it") -> dict:
    labels = {
        "it": {
            "index_sync": "Sincronizzazione cache e indice LTFS",
            "mapping_release": "Rilascio lettera di unita",
            "eject": "Espulsione cassetta",
            "learning": "In apprendimento",
            "stage": "Fase",
        },
        "en": {
            "index_sync": "Synchronizing LTFS cache and index",
            "mapping_release": "Releasing drive letter", "eject": "Ejecting tape",
            "learning": "Learning", "stage": "Stage",
        },
        "fr": {
            "index_sync": "Synchronisation du cache et de l'index LTFS",
            "mapping_release": "Liberation de la lettre de lecteur", "eject": "Ejection de la cassette",
            "learning": "Apprentissage", "stage": "Phase",
        },
        "de": {
            "index_sync": "LTFS-Cache und Index synchronisieren",
            "mapping_release": "Laufwerksbuchstaben freigeben", "eject": "Band auswerfen",
            "learning": "Lernphase", "stage": "Phase",
        },
        "es": {
            "index_sync": "Sincronizacion de cache e indice LTFS",
            "mapping_release": "Liberacion de letra de unidad", "eject": "Expulsion del cartucho",
            "learning": "Aprendiendo", "stage": "Fase",
        },
    }.get(language)
    if labels is None:
        labels = {
            "index_sync": "Sincronizzazione cache e indice LTFS",
            "mapping_release": "Rilascio lettera di unita", "eject": "Espulsione cassetta",
            "learning": "In apprendimento", "stage": "Fase",
        }
    kind = str(event.get("event") or "")
    if kind != "unmount.progress":
        raise ValidationError(
            "Il monitor di finalizzazione cassetta accetta solo eventi di unmount"
        )
    elapsed = max(0.0, float(event.get("elapsed_seconds") or 0.0))
    eta = event.get("eta_seconds")
    stage = str(event.get("stage") or "index_sync")
    number = max(1, int(event.get("stage_number") or 1))
    total = max(number, int(event.get("stage_total") or 3))
    completed = number if event.get("status") == "complete" else number - 1
    return {
        "phase": labels.get(stage, stage),
        "percent": completed / total * 100.0,
        "counter": f"{labels['stage']} {number} / {total}",
        "elapsed": format_duration(elapsed, language=language),
        "eta": format_duration(eta, language=language) if eta is not None else labels["learning"],
        "detail": labels["learning"] if eta is None else "",
    }


def advance_write_timing(event: dict, additional_elapsed_seconds: float) -> dict:
    """Advance tape timing locally while StoreOpen is inside a blocking call."""

    advanced = dict(event)
    elapsed = max(
        0.0,
        float(event.get("cassette_elapsed_seconds") or 0.0)
        + max(0.0, float(additional_elapsed_seconds)),
    )
    cassette_copied = max(0, int(event.get("cassette_copied_bytes") or 0))
    job_copied = max(0, int(event.get("job_copied_bytes") or 0))
    average = cassette_copied / elapsed if elapsed > 0 and cassette_copied > 0 else 0.0
    cassette_remaining = max(
        0, int(event.get("cassette_planned_bytes") or 0) - cassette_copied
    )
    job_remaining = max(0, int(event.get("job_planned_bytes") or 0) - job_copied)
    advanced.update(
        cassette_elapsed_seconds=elapsed,
        average_write_bps=average,
        cassette_eta_seconds=cassette_remaining / average if average > 0 else None,
        job_eta_seconds=job_remaining / average if average > 0 else None,
    )
    return advanced


def write_timing_view(event: dict, *, language: str = "it") -> dict[str, str]:
    """Build the three-part tape timeline shown in the automatic-job console."""

    labels = {
        "it": ("TEMPO TRASCORSO", "FINE CASSETTA", "FINE SET"),
        "en": ("ELAPSED", "TAPE COMPLETE", "SET COMPLETE"),
        "fr": ("TEMPS ECOULE", "FIN DE BANDE", "FIN DU LOT"),
        "de": ("VERSTRICHEN", "BANDENDE", "SATZENDE"),
        "es": ("TRANSCURRIDO", "FIN DE CINTA", "FIN DEL CONJUNTO"),
    }.get(language, ("TEMPO TRASCORSO", "FINE CASSETTA", "FINE SET"))
    return {
        "elapsed_label": labels[0],
        "elapsed": format_duration(event.get("cassette_elapsed_seconds"), language=language),
        "tape_eta_label": labels[1],
        "tape_eta": format_duration(event.get("cassette_eta_seconds"), language=language),
        "job_eta_label": labels[2],
        "job_eta": format_duration(event.get("job_eta_seconds"), language=language),
    }


def copy_activity_text(
    event: dict,
    elapsed_seconds: int,
    *,
    language: str = "it",
) -> str:
    """Describe a blocking LTFS copy phase without inventing byte progress."""

    translations = {
        "it": {
            "read": "Lettura SMB in corso",
            "write": "StoreOpen sta completando la scrittura",
            "flush": "StoreOpen sta completando la scrittura fisica e il flush LTFS",
            "close": "StoreOpen sta chiudendo il file LTFS",
            "close_queue": "Attesa disponibilita pipeline di chiusura LTFS",
            "verify": "StoreOpen sta verificando il file LTFS",
            "finalize": "StoreOpen sta finalizzando i file LTFS a fine lotto",
            "block": "blocco",
            "files": "file",
        },
        "en": {
            "read": "SMB read in progress",
            "write": "StoreOpen is completing the write",
            "flush": "StoreOpen is completing physical write and LTFS flush",
            "close": "StoreOpen is closing the LTFS file",
            "close_queue": "Waiting for the LTFS close pipeline",
            "verify": "StoreOpen is verifying the LTFS file",
            "finalize": "StoreOpen is finalizing LTFS files at batch end",
            "block": "block",
            "files": "files",
        },
        "fr": {
            "read": "Lecture SMB en cours",
            "write": "StoreOpen termine l'ecriture",
            "flush": "StoreOpen termine l'ecriture physique et le vidage LTFS",
            "close": "StoreOpen ferme le fichier LTFS",
            "close_queue": "Attente du pipeline de fermeture LTFS",
            "verify": "StoreOpen verifie le fichier LTFS",
            "finalize": "StoreOpen finalise les fichiers LTFS en fin de lot",
            "block": "bloc",
            "files": "fichiers",
        },
        "de": {
            "read": "SMB-Lesevorgang lauft",
            "write": "StoreOpen schliesst den Schreibvorgang ab",
            "flush": "StoreOpen beendet das physische Schreiben und den LTFS-Flush",
            "close": "StoreOpen schliesst die LTFS-Datei",
            "close_queue": "Warten auf die LTFS-Schliesspipeline",
            "verify": "StoreOpen pruft die LTFS-Datei",
            "finalize": "StoreOpen finalisiert die LTFS-Dateien am Satzende",
            "block": "Block",
            "files": "Dateien",
        },
        "es": {
            "read": "Lectura SMB en curso",
            "write": "StoreOpen esta completando la escritura",
            "flush": "StoreOpen completa la escritura fisica y el vaciado LTFS",
            "close": "StoreOpen esta cerrando el archivo LTFS",
            "close_queue": "Esperando la canalizacion de cierre LTFS",
            "verify": "StoreOpen esta verificando el archivo LTFS",
            "finalize": "StoreOpen finaliza los archivos LTFS al final del lote",
            "block": "bloque",
            "files": "archivos",
        },
    }
    labels = translations.get(language, translations["it"])
    phase = str(event.get("phase") or "write.pending").split(".", 1)[0]
    action = labels.get(phase, labels["write"])
    if phase == "finalize":
        text = action
        text += f"  |  {max(0, int(event.get('pending_files') or 0))} {labels['files']}"
    else:
        relative_path = str(event.get("relative_path") or "-")
        text = f"{action}: {relative_path}"
    if phase == "write":
        pending_bytes = human_bytes(max(0, int(event.get("pending_bytes") or 0)))
        text += f"  |  {labels['block']} {pending_bytes}"
    return f"{text}  |  {max(0, elapsed_seconds)}s"


def tape_activity_text(event: dict, *, language: str = "it") -> str:
    """Describe read-only LTFS/SCSI telemetry without implying copy progress."""

    translations = {
        "it": {
            "unavailable": "Telemetria drive non disponibile; monitoraggio applicativo attivo",
            "buffered": "Attivita LTFS: scrittura/flush del buffer LTFS",
            "positioning": "Attivita LTFS: nastro in movimento o posizionamento",
            "idle": "Attivita LTFS: nessun movimento rilevato",
            "alert": "Attenzione drive: TapeAlert attivi",
            "buffer": "buffer",
            "objects": "oggetti",
            "partition": "partizione",
            "position": "posizione",
        },
        "en": {
            "unavailable": "Drive telemetry unavailable; application monitoring remains active",
            "buffered": "LTFS activity: writing/flushing the LTFS buffer",
            "positioning": "LTFS activity: tape moving or positioning",
            "idle": "LTFS activity: no movement detected",
            "alert": "Drive warning: active TapeAlert flags",
            "buffer": "buffer", "objects": "objects", "partition": "partition", "position": "position",
        },
        "fr": {
            "unavailable": "Telemetrie du lecteur indisponible ; suivi applicatif actif",
            "buffered": "Activite LTFS : ecriture/vidage du tampon LTFS",
            "positioning": "Activite LTFS : bande en mouvement ou positionnement",
            "idle": "Activite LTFS : aucun mouvement detecte",
            "alert": "Alerte lecteur : TapeAlert actifs",
            "buffer": "tampon", "objects": "objets", "partition": "partition", "position": "position",
        },
        "de": {
            "unavailable": "Laufwerkstelemetrie nicht verfugbar; Anwendungsmonitoring aktiv",
            "buffered": "LTFS-Aktivitat: LTFS-Puffer wird geschrieben/geleert",
            "positioning": "LTFS-Aktivitat: Bandbewegung oder Positionierung",
            "idle": "LTFS-Aktivitat: keine Bewegung erkannt",
            "alert": "Laufwerkwarnung: aktive TapeAlerts",
            "buffer": "Puffer", "objects": "Objekte", "partition": "Partition", "position": "Position",
        },
        "es": {
            "unavailable": "Telemetria de la unidad no disponible; monitorizacion de la aplicacion activa",
            "buffered": "Actividad LTFS: escritura/vaciado del bufer LTFS",
            "positioning": "Actividad LTFS: cinta en movimiento o posicionamiento",
            "idle": "Actividad LTFS: no se detecta movimiento",
            "alert": "Aviso de unidad: TapeAlert activos",
            "buffer": "bufer", "objects": "objetos", "partition": "particion", "position": "posicion",
        },
    }
    labels = translations.get(language, translations["it"])
    activity = str(event.get("activity") or "unavailable")
    text = labels.get(activity, labels["unavailable"])
    details: list[str] = []
    if event.get("buffered_bytes") is not None:
        details.append(f"{labels['buffer']} {human_bytes(int(event['buffered_bytes']))}")
    if int(event.get("buffered_objects") or 0):
        details.append(f"{labels['objects']} {int(event['buffered_objects'])}")
    if event.get("partition") is not None and event.get("available") is not False:
        details.append(f"{labels['partition']} {int(event['partition'])}")
    if event.get("first_logical_object") is not None:
        details.append(f"{labels['position']} {int(event['first_logical_object'])}")
    alerts = [int(value) for value in event.get("tape_alerts") or []]
    if alerts:
        details.append("TapeAlert " + ", ".join(str(value) for value in alerts))
    return text + ("  |  " + "  |  ".join(details) if details else "")


def tape_capacity_view(event: dict, *, language: str = "it") -> dict:
    """Format the mounted tape capacity without hiding the safety reserve."""
    labels = {
        "it": ("Disponibile per la scrittura", "Libero rilevato da LTFS", "Margine operativo", "Limite applicativo"),
        "en": ("Available for writing", "Free space reported by LTFS", "Operating margin", "Application limit"),
        "fr": ("Disponible pour l’écriture", "Espace libre signalé par LTFS", "Marge opérationnelle", "Limite applicative"),
        "de": ("Zum Schreiben verfügbar", "Von LTFS gemeldeter freier Speicher", "Betriebsreserve", "Anwendungslimit"),
        "es": ("Disponible para escritura", "Espacio libre indicado por LTFS", "Margen operativo", "Límite de aplicación"),
    }.get(language, ("Disponibile per la scrittura", "Libero rilevato da LTFS", "Margine operativo", "Limite applicativo"))
    overhead_label = {
        "it": "Allocazione e metadati LTFS",
        "en": "LTFS allocation and metadata",
        "fr": "Allocation et metadonnees LTFS",
        "de": "LTFS-Zuweisung und Metadaten",
        "es": "Asignacion y metadatos LTFS",
    }.get(language, "Allocazione e metadati LTFS")
    separator = " : " if language == "fr" else ": "
    return {
        "percent": max(0.0, min(100.0, float(event.get("tape_used_percent") or 0.0))),
        "remaining": f"{labels[0]}{separator}{human_bytes(int(event.get('tape_remaining_bytes') or 0))}",
        "ltfs_free": f"{labels[1]}{separator}{human_bytes(int(event.get('tape_initial_free_bytes') or 0))}",
        "reserve": f"{labels[2]}{separator}{human_bytes(int(event.get('tape_reserve_bytes') or 0))}",
        "limit": f"{labels[3]}{separator}{human_bytes(int(event.get('tape_application_limit_bytes') or 0))}",
        "overhead": f"{overhead_label}{separator}{human_bytes(int(event.get('tape_ltfs_overhead_bytes') or 0))}",
    }


def explorer_library_signature(libraries: list[dict]) -> tuple:
    return tuple(
        (
            str(row.get("id", "")),
            str(row.get("name", "")),
            str(row.get("source_root", "")),
            str(row.get("status", "")),
        )
        for row in libraries
    )


def choose_existing_job_action(job: dict, cassettes: list[dict], labels: list[str]) -> str:
    """Choose the single existing-job action exposed by the GUI."""

    status = str(job.get("status") or "")
    has_new_labels = any(str(label).strip() for label in labels)
    unfinished = next(
        (
            row for row in cassettes
            if row.get("status") != "completed"
            and not (
                row.get("status") == "pending"
                and int(row.get("planned_files") or 0) == 0
                and int(row.get("planned_bytes") or 0) == 0
            )
        ),
        None,
    )
    failed_cassette_message = (
        f"La cassetta {unfinished.get('sequence', '-')} e in errore. "
        "Controllare il dettaglio del job prima di aggiungere altri supporti"
        if status == "failed" and unfinished
        else None
    )
    if has_new_labels:
        if status not in {"completed", "failed", "planned", "paused", "waiting_media"}:
            raise ValidationError(
                "Il job non e in un checkpoint sicuro per aggiungere nuove cassette"
            )
        if failed_cassette_message:
            raise ValidationError(failed_cassette_message)
        return "extend"

    reserves = [
        row for row in cassettes
        if row.get("status") == "pending"
        and int(row.get("planned_files") or 0) == 0
        and int(row.get("planned_bytes") or 0) == 0
    ]
    if status in {"planned", "paused", "waiting_media"}:
        return "resume"
    if status == "completed":
        return "resume"
    if failed_cassette_message:
        raise ValidationError(failed_cassette_message)
    if status == "failed":
        raise ValidationError(
            "Il job richiede nuove cassette. Inserire le etichette nel riquadro e "
            "premere di nuovo il pulsante"
        )
    raise ValidationError(f"Il job nello stato {status or '-'} non puo essere ripreso")


def failed_cassette_to_retry(job: dict, cassettes: list[dict]) -> dict | None:
    if str(job.get("status") or "") != "failed":
        return None
    return next(
        (row for row in cassettes if row.get("status") == "failed"),
        None,
    )


def should_reset_backup_explorer(
    explorer_mode: str,
    current_signature: tuple,
    new_signature: tuple,
) -> bool:
    return explorer_mode != "search" or current_signature != new_signature


def exercise_responsive_layouts(window: "LtoBackupWindow") -> None:
    """Exercise both layout modes and every page during packaged smoke tests."""

    for mode in ("compact", "wide"):
        window._apply_responsive_layout(mode)
        window._show_page("automatic")
        window._set_automatic_finalization_active(True)
        window.automatic_state.set("Scrittura")
        window.automatic_write_speed.set("Media effettiva cassetta: -")
        window.automatic_ltfs_activity.set("Telemetria LTFS: -")
        window.automatic_selected_job_action.set("In attesa")
        window.automatic_elapsed_time.set("-")
        window.automatic_tape_eta.set("-")
        window.automatic_job_eta.set("-")
        window.automatic_tape_capacity_title.set("CASSETTA CORRENTE")
        window.automatic_tape_remaining.set("Disponibile: -")
        window.automatic_tape_ltfs_free.set("Libero LTFS: -")
        window.automatic_tape_policy.set("Limite: -")
        window.automatic_finalize_phase.set("Inattivo")
        window.automatic_finalize_detail.set("Nessuna finalizzazione in corso")
        window.automatic_finalize_counter.set("-")
        window.automatic_finalize_elapsed.set("-")
        window.automatic_finalize_eta.set("-")
        window.status_var.set("Pronto")
        window.update_idletasks()
        fields = (
            window.automatic_state_field,
            window.automatic_speed_field,
            window.automatic_ltfs_field,
            window.automatic_selected_action_field,
            window.automatic_finalize_phase_field,
            window.automatic_finalize_detail_field,
            window.automatic_tape_capacity_title_field,
            window.automatic_tape_remaining_field,
            window.automatic_tape_ltfs_free_field,
            window.automatic_tape_policy_field,
            window.status_message_field,
            *window.automatic_timing_cells,
            *window.automatic_finalize_cells,
        )
        panels = (
            window.automatic_state_panel,
            window.automatic_speed_chart,
            window.automatic_timing_rail,
            window.automatic_finalize_panel,
            window.automatic_finalize_metrics,
            window.status_frame,
            window.footer_progress,
            *window.automatic_timing_cells,
            *window.automatic_finalize_cells,
        )
        before_requested = tuple(
            (field.winfo_reqwidth(), field.winfo_reqheight()) for field in fields
        )
        before_geometry = tuple(
            (panel.winfo_x(), panel.winfo_y(), panel.winfo_width(), panel.winfo_height())
            for panel in panels
        )
        window.automatic_state.set(
            "StoreOpen sta completando una fase LTFS con una descrizione operativa molto lunga"
        )
        window.automatic_write_speed.set(
            "Media effettiva cassetta: 143.05 MiB/s | invio alla cache LTFS: in attesa di conferma"
        )
        window.automatic_ltfs_activity.set(
            "StoreOpen sta completando la scrittura fisica di un file con percorso molto lungo"
        )
        window.automatic_selected_job_action.set(
            "StoreOpen sta passando dal buffering alla scrittura senza modificare il layout"
        )
        window.automatic_elapsed_time.set("123g 23:59:59")
        window.automatic_tape_eta.set("456g 23:59:59")
        window.automatic_job_eta.set("789g 23:59:59")
        window.automatic_tape_capacity_title.set(
            "CASSETTA CORRENTE | ETICHETTA-FISICA-MOLTO-LUNGA"
        )
        window.automatic_tape_remaining.set(
            "Disponibile per la scrittura: 999.99 GiB"
        )
        window.automatic_tape_ltfs_free.set(
            "Libero rilevato da LTFS: 1.23 TiB"
        )
        window.automatic_tape_policy.set(
            "Limite applicativo: 2.34 TiB | Margine operativo: 100.00 GiB"
        )
        window.automatic_finalize_phase.set(
            "Sincronizzazione cache e indice LTFS con descrizione lunga"
        )
        window.automatic_finalize_detail.set(
            "StoreOpen sta consolidando l'indice della cassetta corrente"
        )
        window.automatic_finalize_counter.set("Fase 3 / 3")
        window.automatic_finalize_elapsed.set("123g 23:59:59")
        window.automatic_finalize_eta.set("456g 23:59:59")
        window.status_var.set(
            "StoreOpen sta finalizzando il lotto e aggiornando il catalogo persistente"
        )
        window.update_idletasks()
        after_requested = tuple(
            (field.winfo_reqwidth(), field.winfo_reqheight()) for field in fields
        )
        after_geometry = tuple(
            (panel.winfo_x(), panel.winfo_y(), panel.winfo_width(), panel.winfo_height())
            for panel in panels
        )
        if after_requested != before_requested or after_geometry != before_geometry:
            raise RuntimeError(
                f"Geometria job instabile in modalita {mode}: "
                f"req {before_requested!r} -> {after_requested!r}; "
                f"layout {before_geometry!r} -> {after_geometry!r}"
            )
        window._set_automatic_finalization_active(False)
    for item in NAVIGATION_ITEMS:
        window._show_page(item.key)
        window.update_idletasks()
    window.destroy()


def build_automatic_job_view(job: dict, cassettes: list[dict]) -> dict:
    """Build the operator-facing state of an automatic job and its tape queue."""

    ordered = sorted(cassettes, key=lambda row: int(row.get("sequence", 0)))
    queue_cassettes = int(job.get("total_cassettes") or len(ordered))
    reserved_rows = [
        row for row in ordered
        if row.get("status") == "pending"
        and int(row.get("planned_files") or 0) == 0
        and int(row.get("planned_bytes") or 0) == 0
    ]
    active_rows = [row for row in ordered if row not in reserved_rows]
    total_cassettes = len(active_rows)
    reserved_cassettes = len(reserved_rows)
    completed_cassettes = sum(row.get("status") == "completed" for row in ordered)
    planned_files = sum(int(row.get("planned_files") or 0) for row in ordered)
    planned_bytes = sum(int(row.get("planned_bytes") or 0) for row in ordered)
    copied_files = sum(int(row.get("copied_files") or 0) for row in ordered)
    copied_bytes = sum(int(row.get("copied_bytes") or 0) for row in ordered)
    status = job.get("status", "planned")
    retryable = failed_cassette_to_retry(job, ordered)
    current = next(
        (
            row for row in active_rows
            if row.get("status") != "completed"
        ),
        None,
    )

    if planned_bytes:
        progress_percent = min(100.0, copied_bytes * 100.0 / planned_bytes)
    elif total_cassettes:
        progress_percent = min(100.0, completed_cassettes * 100.0 / total_cassettes)
    else:
        progress_percent = 100.0 if status == "completed" else 0.0
    if status == "completed":
        progress_percent = 100.0
        next_label = "-"
        if reserved_cassettes:
            callout = (
                f"Job completato: dati attuali archiviati; {reserved_cassettes} "
                f"{'cassetta' if reserved_cassettes == 1 else 'cassette'} in riserva futura."
            )
        else:
            callout = "Job completato: tutte le cassette sono state scritte ed espulse."
    elif status == "failed":
        next_label = str(current.get("physical_label") or "-") if current else "-"
        callout = f"Job fermo: {job.get('last_error') or 'controllare il dettaglio.'}"
    elif current:
        next_label = str(current.get("physical_label") or "-")
        if status == "planned":
            operation = (
                "prima cassetta APPEND (nessuna formattazione)"
                if current.get("operation") == "append"
                else "prima cassetta"
            )
            callout = (
                "Job salvato, non e in esecuzione. Premi Avvia / riprendi; "
                f"{operation}: {next_label}"
            )
        elif current.get("operation") == "append":
            action = {
                "mounting": "Mount LTFS per APPEND (nessuna formattazione)",
                "writing": "APPEND in corso (dati esistenti conservati)",
                "unmounting": "Chiusura APPEND ed espulsione",
                "paused": "Job in pausa. Prossima cassetta APPEND (nessuna formattazione)",
            }.get(status, "Inserire per APPEND (nessuna formattazione)")
            callout = f"{action}: {next_label}"
        else:
            action = {
                "formatting": "Formattazione in corso",
                "mounting": "Mount LTFS in corso",
                "writing": "Scrittura in corso",
                "unmounting": "Chiusura ed espulsione",
                "paused": "Job in pausa. Prossima cassetta",
            }.get(status, "Inserire ora")
            callout = f"{action}: {next_label}"
    else:
        next_label = "-"
        callout = "Nessuna cassetta in coda."

    if status == "completed":
        checkpoint = (
            f"CHECKPOINT FINALE  |  {completed_cassettes} / {total_cassettes} cassette completate"
            "  |  Job concluso"
            + (
                f"  |  Riserva futura: {reserved_cassettes}"
                if reserved_cassettes else ""
            )
        )
    elif status == "failed":
        checkpoint = (
            f"STATO SALVATO  |  ultimo checkpoint sicuro: {completed_cassettes} / "
            f"{total_cassettes} cassette  |  Verificare l'errore prima di continuare"
        )
    elif status in {"formatting", "mounting", "writing", "unmounting"}:
        sequence = int(current.get("sequence") or 0) if current else 0
        checkpoint = (
            f"IN ESECUZIONE  |  checkpoint sicuro: {completed_cassettes} / {total_cassettes} cassette"
            f"  |  Cassetta corrente {sequence} / {total_cassettes}: {next_label}"
        )
    elif status == "planned" and current:
        sequence = int(current.get("sequence") or 0)
        checkpoint = (
            f"JOB SALVATO  |  non avviato  |  Avvio: {sequence} / "
            f"{total_cassettes} {next_label}"
        )
    elif current:
        sequence = int(current.get("sequence") or 0)
        restart = "Partenza" if completed_cassettes == 0 else "Ripartenza"
        checkpoint = (
            f"CHECKPOINT SALVATO  |  {completed_cassettes} / {total_cassettes} cassette completate"
            f"  |  {restart}: {sequence} / {total_cassettes} {next_label}"
        )
    else:
        checkpoint = "JOB SALVATO  |  Nessuna cassetta pianificata"

    decorated = []
    for row in ordered:
        item = dict(row)
        row_status = item.get("status")
        if row in reserved_rows:
            marker, tag = "[R]", "queue_reserved"
        elif row_status == "completed":
            marker, tag = "[OK]", "queue_done"
        elif row_status == "failed":
            marker, tag = "[!]", "queue_failed"
        elif current is row:
            marker, tag = "[ORA]", "queue_current"
        else:
            marker, tag = "[ ]", "queue_pending"
        if tag == "queue_reserved":
            operation_label = "RISERVA - non formattata"
        elif item.get("operation") == "append":
            operation_label = "APPEND - conserva i dati"
        else:
            operation_label = "NUOVA - formatta LTFS"
        item.update(marker=marker, tag=tag, operation_label=operation_label)
        decorated.append(item)

    return {
        "completed_cassettes": completed_cassettes,
        "total_cassettes": total_cassettes,
        "queue_cassettes": queue_cassettes,
        "active_cassettes": total_cassettes,
        "reserved_cassettes": reserved_cassettes,
        "planned_files": planned_files,
        "planned_bytes": planned_bytes,
        "copied_files": copied_files,
        "copied_bytes": copied_bytes,
        "progress_percent": progress_percent,
        "next_label": next_label,
        "callout": callout,
        "checkpoint": checkpoint,
        "retry_sequence": int(retryable["sequence"]) if retryable else None,
        "retry_label": str(retryable.get("physical_label") or "-") if retryable else None,
        "cassettes": decorated,
    }


def automatic_job_label(job: dict) -> str:
    return str(job.get("display_name") or job.get("id") or "-")


class ProgressTracker:
    """Turns engine events into values suitable for a graphical progress bar."""

    def __init__(self) -> None:
        self.total_bytes = 0
        self.completed_bytes = 0
        self.total_files = 0

    def reset(self) -> None:
        self.total_bytes = 0
        self.completed_bytes = 0
        self.total_files = 0

    def update(self, event: dict) -> ProgressView:
        kind = event.get("event", "")
        if kind in {"batch.scan.start", "batch.scan.complete"}:
            index = int(event.get("index", 0))
            total = max(1, int(event.get("total", 1)))
            library_id = str(event.get("library_id") or "")
            if kind == "batch.scan.start":
                return ProgressView(
                    max(0.0, (index - 1) * 100.0 / total),
                    f"Preparazione scrittura {index}/{total}: scansione {library_id}",
                )
            return ProgressView(
                min(100.0, index * 100.0 / total),
                f"Preparazione {index}/{total} completata: {library_id}",
            )
        if kind in {"library.scan.start", "library.scan.complete"}:
            index = int(event.get("index", 0))
            total = max(1, int(event.get("total", 1)))
            library_id = event.get("library_id", "")
            if kind == "library.scan.start":
                return ProgressView(
                    max(0.0, (index - 1) * 100.0 / total),
                    f"Scansione libreria {index}/{total}: {library_id}",
                )
            return ProgressView(
                min(100.0, index * 100.0 / total),
                f"Libreria {index}/{total} completata: {library_id} — "
                f"{event.get('files', 0)} file / {human_bytes(int(event.get('bytes', 0)))}",
            )
        if kind == "plan":
            self.total_bytes = int(event.get("bytes", 0))
            self.total_files = int(event.get("files", 0))
            pending_files = int(event.get("pending_files", self.total_files))
            estimated_tapes = int(event.get("estimated_tapes", 1 if pending_files else 0))
            return ProgressView(
                0.0,
                f"Lotto sul nastro corrente: {self.total_files} file, {human_bytes(self.total_bytes)}; "
                f"totale pendente {pending_files} file su circa {estimated_tapes} cassette",
            )
        if kind == "file.start":
            return ProgressView(self._percent(self.completed_bytes), f"Copia: {event.get('relative_path', '')}")
        if kind == "file.progress":
            current = int(event.get("copied_bytes", 0))
            return ProgressView(
                self._percent(self.completed_bytes + current),
                f"Copia: {event.get('relative_path', '')}",
            )
        if kind == "file.complete":
            self.completed_bytes = int(event.get("copied_bytes", self.completed_bytes))
            return ProgressView(
                self._percent(self.completed_bytes),
                f"Completato {event.get('index', 0)}/{event.get('total_files', self.total_files)}: "
                f"{event.get('relative_path', '')}",
            )
        if kind == "restore.complete":
            index = int(event.get("index", 0))
            total = max(1, int(event.get("total_files", 1)))
            return ProgressView(
                min(100.0, index * 100.0 / total),
                f"Ripristinato {index}/{total}: {event.get('relative_path', '')}",
            )
        if kind == "restore.skip":
            return ProgressView(0.0, f"Già presente: {event.get('relative_path', '')}")
        if kind == "block.complete":
            return ProgressView(100.0, "Blocco completato e catalogato")
        if kind == "catalog.snapshot.warning":
            return ProgressView(self._percent(self.completed_bytes), "Avviso: snapshot catalogo non scritto")
        if kind == "block.failed":
            return ProgressView(self._percent(self.completed_bytes), f"Backup interrotto: {event.get('error', '')}")
        return ProgressView(self._percent(self.completed_bytes), kind)

    def _percent(self, value: int) -> float:
        if self.total_bytes <= 0:
            return 0.0
        return min(100.0, value * 100.0 / self.total_bytes)


class LibraryDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc):
        super().__init__(parent)
        self.title("Aggiungi libreria SMB")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result: tuple[str, str, str] | None = None

        panel = ttk.Frame(self, padding=20)
        panel.grid(sticky="nsew")
        self.id_var = tk.StringVar()
        self.name_var = tk.StringVar()
        self.source_var = tk.StringVar()
        self._field(panel, 0, "ID libreria", self.id_var)
        self._field(panel, 1, "Nome", self.name_var)
        ttk.Label(panel, text="Percorso SMB o cartella").grid(row=4, column=0, sticky="w", pady=(10, 4))
        entry = ttk.Entry(panel, textvariable=self.source_var, width=55)
        entry.grid(row=5, column=0, sticky="ew")
        ttk.Button(panel, text="Sfoglia…", command=self._browse).grid(row=5, column=1, padx=(8, 0))
        ttk.Label(
            panel,
            text=r"Esempio: \\nas\archivio\media",
            foreground="#64748b",
        ).grid(row=6, column=0, sticky="w", pady=(4, 14))

        buttons = ttk.Frame(panel)
        buttons.grid(row=7, column=0, columnspan=2, sticky="e")
        ttk.Button(buttons, text="Annulla", command=self.destroy).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Aggiungi", style="Accent.TButton", command=self._accept).pack(side="left")
        self.bind("<Return>", lambda _event: self._accept())
        self.bind("<Escape>", lambda _event: self.destroy())
        self.after(50, lambda: self.focus_force())

    @staticmethod
    def _field(parent: ttk.Frame, row: int, label: str, variable: tk.StringVar) -> None:
        ttk.Label(parent, text=label).grid(row=row * 2, column=0, sticky="w", pady=(0 if row == 0 else 10, 4))
        ttk.Entry(parent, textvariable=variable, width=55).grid(row=row * 2 + 1, column=0, columnspan=2, sticky="ew")

    def _browse(self) -> None:
        selected = filedialog.askdirectory(parent=self, title="Seleziona la libreria")
        if selected:
            self.source_var.set(selected)

    def _accept(self) -> None:
        values = tuple(value.strip() for value in (self.id_var.get(), self.name_var.get(), self.source_var.get()))
        if not all(values):
            messagebox.showwarning("Dati mancanti", "Compilare ID, nome e percorso sorgente.", parent=self)
            return
        self.result = values  # type: ignore[assignment]
        self.destroy()


class TapeDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        initial_tape_id: str = "",
        initial_cassette_number: str = "",
        initial_mount: str = "L:\\",
    ):
        super().__init__(parent)
        self.title("Registra cassetta LTFS")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result: tuple[str, str, str] | None = None

        panel = ttk.Frame(self, padding=20)
        panel.grid(sticky="nsew")
        self.tape_id_var = tk.StringVar(value=initial_tape_id)
        self.cassette_number_var = tk.StringVar(value=initial_cassette_number)
        self.mount_var = tk.StringVar(value=initial_mount)
        fields = (
            ("ID tecnico nastro", self.tape_id_var),
            ("Numero cassetta", self.cassette_number_var),
            ("Mount LTFS", self.mount_var),
        )
        for index, (label, variable) in enumerate(fields):
            ttk.Label(panel, text=label).grid(row=index * 2, column=0, sticky="w", pady=(0 if index == 0 else 10, 4))
            ttk.Entry(panel, textvariable=variable, width=46).grid(row=index * 2 + 1, column=0, sticky="ew")
        ttk.Button(panel, text="Sfoglia…", command=self._browse).grid(row=5, column=1, padx=(8, 0))
        ttk.Label(
            panel,
            text="Il numero cassetta deve coincidere con l'etichetta fisica.",
            foreground="#64748b",
        ).grid(row=6, column=0, columnspan=2, sticky="w", pady=(6, 14))
        buttons = ttk.Frame(panel)
        buttons.grid(row=7, column=0, columnspan=2, sticky="e")
        ttk.Button(buttons, text="Annulla", command=self.destroy).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Registra", style="Accent.TButton", command=self._accept).pack(side="left")
        self.bind("<Return>", lambda _event: self._accept())
        self.bind("<Escape>", lambda _event: self.destroy())
        self.after(50, lambda: self.focus_force())

    def _browse(self) -> None:
        selected = filedialog.askdirectory(parent=self, title="Seleziona il volume LTFS")
        if selected:
            self.mount_var.set(selected)

    def _accept(self) -> None:
        values = tuple(
            value.strip()
            for value in (self.tape_id_var.get(), self.cassette_number_var.get(), self.mount_var.get())
        )
        if not all(values):
            messagebox.showwarning(
                "Dati mancanti",
                "Compilare ID tecnico, numero cassetta e mount LTFS.",
                parent=self,
            )
            return
        self.result = values  # type: ignore[assignment]
        self.destroy()


class LibrarySelectionDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, libraries: list[dict], selected: list[str]):
        super().__init__(parent)
        self.title("Seleziona librerie per il job")
        self.geometry("560x430")
        self.minsize(460, 340)
        self.transient(parent)
        self.grab_set()
        self.result: list[str] | None = None
        self.libraries = libraries

        panel = ttk.Frame(self, padding=18)
        panel.pack(fill="both", expand=True)
        ttk.Label(
            panel,
            text="Selezionare una o piu librerie. Il piano cassette sara calcolato sul loro contenuto cumulativo.",
            wraplength=510,
        ).pack(anchor="w", pady=(0, 10))
        self.listbox = tk.Listbox(
            panel,
            selectmode="extended",
            exportselection=False,
            font=("Segoe UI Variable Text", 10),
            activestyle="dotbox",
        )
        self.listbox.pack(fill="both", expand=True)
        selected_keys = {value.casefold() for value in selected}
        for index, row in enumerate(libraries):
            self.listbox.insert("end", f"{row['id']}  —  {row['name']}  —  {row['source_root']}")
            if row["id"].casefold() in selected_keys:
                self.listbox.selection_set(index)

        buttons = ttk.Frame(panel)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, text="Seleziona tutte", command=lambda: self.listbox.selection_set(0, "end")).pack(side="left")
        ttk.Button(buttons, text="Nessuna", command=lambda: self.listbox.selection_clear(0, "end")).pack(side="left", padx=8)
        ttk.Button(buttons, text="Annulla", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="Conferma", style="Accent.TButton", command=self._accept).pack(side="right", padx=8)
        self.bind("<Escape>", lambda _event: self.destroy())

    def _accept(self) -> None:
        indexes = self.listbox.curselection()
        if not indexes:
            messagebox.showwarning("Librerie", "Selezionare almeno una libreria.", parent=self)
            return
        self.result = [self.libraries[index]["id"] for index in indexes]
        self.destroy()


class LtoBackupWindow(tk.Tk):
    BG = "#edf2f4"
    PANEL = "#fcfdfd"
    TEXT = "#142435"
    MUTED = "#60717f"
    SIDEBAR = "#142435"
    SIDEBAR_MUTED = "#91a2af"
    ACCENT = "#d8942f"
    SUCCESS = "#2c7a7b"
    DANGER = "#b84c4c"

    def __init__(self, application: LtoApplication):
        super().__init__()
        self.application = application
        self.language = load_language(self.application.paths.state_dir)
        self._translator = Translator(self.language)
        self.title(f"LTO Archiver {__version__}")
        initial_width, initial_height = fitted_window_size(
            self.winfo_screenwidth(), self.winfo_screenheight()
        )
        self.geometry(f"{initial_width}x{initial_height}")
        self.minsize(min(900, initial_width), min(600, initial_height))
        self.configure(bg=self.BG)
        self.protocol("WM_DELETE_WINDOW", self._close)

        self._events: queue.Queue[tuple] = queue.Queue()
        self._busy = False
        self._action_buttons: list[ttk.Button] = []
        self._nav_buttons: dict[str, tk.Button] = {}
        self._pages: dict[str, ttk.Frame] = {}
        self._page_canvases: dict[str, tk.Canvas] = {}
        self._current_page = "overview"
        self._responsive_mode = ""
        self._snapshot: dict = {"libraries": [], "tapes": [], "blocks": [], "settings": {}}
        self._inventory_library_ids: list[str] = []
        self._inventory_plan: dict | None = None
        self._automatic_library_ids: list[str] = []
        self._automatic_stop_event = threading.Event()
        self._automatic_job_id = ""
        self._automatic_writing = False
        self._automatic_last_write_at: float | None = None
        self._automatic_average_write_bps = 0.0
        self._automatic_live_write_bps: float | None = None
        self._automatic_timing_event: dict | None = None
        self._automatic_timing_updated_at: float | None = None
        self._automatic_activity_event: dict | None = None
        self._automatic_activity_started_at: float | None = None
        self._automatic_finalization_event: dict | None = None
        self._automatic_finalization_updated_at: float | None = None
        self._automatic_telemetry_text = ""
        self.progress_tracker = ProgressTracker()

        self._configure_style()
        self._build_shell()
        self.bind("<Configure>", self._window_resized, add="+")
        self.bind_all("<MouseWheel>", self._page_mousewheel, add="+")
        self.after_idle(lambda: self._apply_responsive_layout(responsive_mode(self.winfo_width())))
        self.after(80, self._poll_events)
        self.after(150, self.refresh)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("TFrame", background=self.BG)
        style.configure("Panel.TFrame", background=self.PANEL)
        style.configure("Workspace.TFrame", background=self.BG)
        style.configure("TLabel", background=self.BG, foreground=self.TEXT, font=("Segoe UI Variable Text", 10))
        style.configure("Panel.TLabel", background=self.PANEL, foreground=self.TEXT, font=("Segoe UI Variable Text", 10))
        style.configure("Title.TLabel", background=self.BG, foreground=self.TEXT, font=("Segoe UI Variable Display Semibold", 24))
        style.configure("Eyebrow.TLabel", background=self.BG, foreground=self.ACCENT, font=("Cascadia Mono SemiBold", 9))
        style.configure("Subtitle.TLabel", background=self.BG, foreground=self.MUTED, font=("Segoe UI Variable Text", 10))
        style.configure("Section.TLabel", background=self.PANEL, foreground=self.TEXT, font=("Segoe UI Variable Display Semibold", 13))
        style.configure("CardValue.TLabel", background=self.PANEL, foreground=self.TEXT, font=("Cascadia Mono SemiBold", 23))
        style.configure("CardLabel.TLabel", background=self.PANEL, foreground=self.MUTED, font=("Segoe UI Variable Text Semibold", 8))
        style.configure("Utility.TLabel", background=self.PANEL, foreground=self.MUTED, font=("Cascadia Mono", 8))
        style.configure("TButton", font=("Segoe UI Variable Text Semibold", 9), padding=(14, 8), background="#e4eaed", foreground=self.TEXT)
        style.map("TButton", background=[("active", "#d7e0e4"), ("disabled", "#eef2f3")])
        style.configure("Accent.TButton", background=self.ACCENT, foreground="#142435", borderwidth=0)
        style.map("Accent.TButton", background=[("active", "#e3a84e"), ("disabled", "#ead9bc")])
        style.configure("Danger.TButton", foreground=self.DANGER)
        style.configure("TNotebook", background=self.PANEL, borderwidth=0, tabmargins=0)
        style.configure("TNotebook.Tab", font=("Segoe UI Variable Text Semibold", 9), padding=(16, 9), background="#e8edef")
        style.map("TNotebook.Tab", background=[("selected", self.PANEL)], foreground=[("selected", self.SUCCESS)])
        style.configure("Treeview", font=("Segoe UI Variable Text", 9), rowheight=31, fieldbackground=self.PANEL, background=self.PANEL, borderwidth=0)
        style.map("Treeview", background=[("selected", "#d8e9e8")], foreground=[("selected", self.TEXT)])
        style.configure("Treeview.Heading", font=("Segoe UI Variable Text Semibold", 9), padding=(8, 9), background="#e4eaed", foreground=self.TEXT, relief="flat")
        style.map("Treeview.Heading", background=[("active", "#d7e0e4")])
        style.configure("TEntry", padding=(8, 7), fieldbackground="#ffffff", bordercolor="#cbd6db")
        style.configure("TCombobox", padding=(8, 7), fieldbackground="#ffffff", bordercolor="#cbd6db")
        style.configure("Horizontal.TProgressbar", background=self.ACCENT, troughcolor="#dbe3e7", borderwidth=0, thickness=12)

    def _build_shell(self) -> None:
        shell = tk.Frame(self, bg=self.BG)
        shell.pack(fill="both", expand=True)
        self.sidebar = tk.Frame(shell, bg=self.SIDEBAR, width=224)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        tk.Frame(self.sidebar, bg=self.ACCENT, width=5).place(x=0, y=0, relheight=1)

        self.main = ttk.Frame(shell, style="Workspace.TFrame")
        self.main.pack(side="left", fill="both", expand=True)
        self._build_sidebar()
        self._build_header()
        self._build_statusbar()
        self.page_host = ttk.Frame(self.main, padding=(28, 0, 28, 18), style="Workspace.TFrame")
        self.page_host.pack(fill="both", expand=True)
        self.page_host.grid_propagate(False)
        self.page_host.columnconfigure(0, weight=1)
        self.page_host.rowconfigure(0, weight=1)
        self._build_pages()
        self._translate_static_widgets(self)
        self._show_page("overview")

    def _t(self, text: str) -> str:
        return self._translator(text)

    def _translate_static_widgets(self, parent: tk.Misc) -> None:
        for widget in parent.winfo_children():
            try:
                text = widget.cget("text")
                if text:
                    widget.configure(text=self._t(str(text)))
            except (tk.TclError, AttributeError):
                pass
            if isinstance(widget, ttk.Treeview):
                for column in widget.cget("columns"):
                    heading = widget.heading(column).get("text", "")
                    if heading:
                        widget.heading(column, text=self._t(str(heading)))
            self._translate_static_widgets(widget)

    def _build_sidebar(self) -> None:
        brand = tk.Frame(self.sidebar, bg=self.SIDEBAR)
        brand.pack(fill="x", padx=(22, 16), pady=(24, 22))
        tk.Label(brand, text="LTO", bg=self.SIDEBAR, fg=self.ACCENT, font=("Cascadia Mono SemiBold", 11)).pack(anchor="w")
        tk.Label(brand, text="ARCHIVER", justify="left", bg=self.SIDEBAR, fg="#ffffff", font=("Segoe UI Variable Display Semibold", 18)).pack(anchor="w", pady=(2, 0))
        tk.Label(brand, text="tape operations", bg=self.SIDEBAR, fg=self.SIDEBAR_MUTED, font=("Cascadia Mono", 8)).pack(anchor="w", pady=(6, 0))

        tk.Label(self.sidebar, text="FLUSSO OPERATIVO", bg=self.SIDEBAR, fg=self.SIDEBAR_MUTED, font=("Cascadia Mono SemiBold", 8)).pack(anchor="w", padx=(22, 0), pady=(2, 8))
        for item in NAVIGATION_ITEMS:
            if item.key == "search":
                tk.Frame(self.sidebar, bg="#33495a", height=1).pack(fill="x", padx=(22, 16), pady=(12, 12))
                tk.Label(self.sidebar, text="STRUMENTI", bg=self.SIDEBAR, fg=self.SIDEBAR_MUTED, font=("Cascadia Mono SemiBold", 8)).pack(anchor="w", padx=(22, 0), pady=(0, 7))
            button = tk.Button(
                self.sidebar,
                text=f"{item.marker or '  '}   {self._t(item.label)}",
                command=lambda key=item.key: self._show_page(key),
                anchor="w",
                relief="flat",
                bd=0,
                padx=18,
                pady=10,
                bg=self.SIDEBAR,
                fg="#d9e2e7" if item.marker else self.SIDEBAR_MUTED,
                activebackground="#20374a",
                activeforeground="#ffffff",
                font=("Segoe UI Variable Text Semibold", 10),
                cursor="hand2",
            )
            button.pack(fill="x", padx=(6, 8), pady=1)
            self._nav_buttons[item.key] = button

        sidebar_footer = tk.Frame(self.sidebar, bg=self.SIDEBAR)
        sidebar_footer.pack(side="bottom", fill="x", padx=(22, 16), pady=20)
        tk.Frame(sidebar_footer, bg="#33495a", height=1).pack(fill="x", pady=(0, 14))
        tk.Label(sidebar_footer, text=f"VERSIONE {__version__}", bg=self.SIDEBAR, fg=self.SIDEBAR_MUTED, font=("Cascadia Mono", 8)).pack(anchor="w")
        tk.Label(sidebar_footer, text="FILE DIRETTI · NO TAR", bg=self.SIDEBAR, fg=self.ACCENT, font=("Cascadia Mono SemiBold", 8)).pack(anchor="w", pady=(4, 0))

        for index, item in enumerate(NAVIGATION_ITEMS, start=1):
            self.bind(f"<Alt-Key-{index}>", lambda _event, key=item.key: self._show_page(key))

    def _build_header(self) -> None:
        header = ttk.Frame(self.main, padding=(28, 22, 28, 16), style="Workspace.TFrame")
        header.pack(fill="x")
        self.header_frame = header
        left = ttk.Frame(header, style="Workspace.TFrame")
        left.pack(side="left", fill="x", expand=True)
        self.header_left = left
        self.page_eyebrow = tk.StringVar(value="ARCHIVIO LTO / PANORAMICA")
        self.page_title = tk.StringVar(value="Centro operativo")
        self.page_subtitle = tk.StringVar(value="Stato dell'archivio e ultime attivita")
        ttk.Label(left, textvariable=self.page_eyebrow, style="Eyebrow.TLabel").pack(anchor="w")
        ttk.Label(left, textvariable=self.page_title, style="Title.TLabel").pack(anchor="w", pady=(2, 0))
        ttk.Label(left, textvariable=self.page_subtitle, style="Subtitle.TLabel").pack(anchor="w", pady=(3, 0))

        state_panel = tk.Frame(header, bg="#dcebea", padx=14, pady=9)
        state_panel.pack(side="right", anchor="n", pady=2)
        self.header_state_panel = state_panel
        self.language_name = tk.StringVar(value=LANGUAGES[self.language])
        language = ttk.Combobox(
            state_panel,
            textvariable=self.language_name,
            values=tuple(LANGUAGES.values()),
            state="readonly",
            width=10,
        )
        language.pack(side="right", padx=(12, 0))
        language.bind("<<ComboboxSelected>>", self._language_changed)
        self.header_state_dot = tk.Label(state_panel, text="●", bg="#dcebea", fg=self.SUCCESS, font=("Segoe UI", 10))
        self.header_state_dot.pack(side="left")
        self.header_state = tk.Label(state_panel, text=" Avvio...", bg="#dcebea", fg=self.TEXT, font=("Segoe UI Variable Text Semibold", 9))
        self.header_state.pack(side="left")

    def _build_pages(self) -> None:
        self._build_overview_tab()
        self._build_libraries_tab()
        self._build_inventory_tab()
        self._build_automatic_tab()
        self._build_backup_tab()
        self._build_restore_tab()
        self._build_search_tab()
        self._build_catalog_tab()

    def _new_tab(self, title: str) -> ttk.Frame:
        key_by_title = {
            "Panoramica": "overview",
            "Librerie": "libraries",
            "Piano del job": "inventory",
            "Job automatici": "automatic",
            "Backup": "backup",
            "Ripristino": "restore",
            "Ricerca file": "search",
            "Catalogo": "catalog",
        }
        outer = ttk.Frame(self.page_host, padding=18, style="Panel.TFrame")
        outer.grid(row=0, column=0, sticky="nsew")
        key = key_by_title[title]
        self._pages[key] = outer
        canvas = tk.Canvas(
            outer, bg=self.PANEL, highlightthickness=0, borderwidth=0,
        )
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        content = ttk.Frame(canvas, style="Panel.TFrame")
        window_id = canvas.create_window((0, 0), window=content, anchor="nw")
        self._page_canvases[key] = canvas

        def sync_page(_event=None) -> None:
            width = max(1, canvas.winfo_width())
            height = max(canvas.winfo_height(), content.winfo_reqheight())
            canvas.itemconfigure(window_id, width=width, height=height)
            canvas.configure(scrollregion=canvas.bbox("all"))

        canvas.bind("<Configure>", sync_page, add="+")
        content.bind("<Configure>", lambda _event: canvas.after_idle(sync_page), add="+")
        return content

    def _window_resized(self, event: tk.Event) -> None:
        if event.widget is self:
            mode = responsive_mode(int(event.width))
            if mode != self._responsive_mode:
                self._apply_responsive_layout(mode)

    def _page_mousewheel(self, event: tk.Event):
        canvas = self._page_canvases.get(self._current_page)
        if canvas is None or not canvas.winfo_exists():
            return None
        pointer_x, pointer_y = self.winfo_pointerxy()
        left, top = canvas.winfo_rootx(), canvas.winfo_rooty()
        if not (left <= pointer_x <= left + canvas.winfo_width() and top <= pointer_y <= top + canvas.winfo_height()):
            return None
        widget = event.widget
        while widget is not None:
            if isinstance(widget, (ttk.Treeview, tk.Text, tk.Listbox)):
                return None
            widget = getattr(widget, "master", None)
        direction = -1 if int(event.delta) > 0 else 1
        canvas.yview_scroll(direction, "units")
        return "break"

    def _apply_responsive_layout(self, mode: str) -> None:
        """Reflow every workspace panel without changing its operational content."""

        compact = mode == "compact"
        self._responsive_mode = mode
        self.sidebar.configure(width=184 if compact else 224)
        self.header_frame.configure(
            padding=(16, 14, 16, 10) if compact else (28, 22, 28, 16)
        )
        self.page_host.configure(
            padding=(16, 0, 16, 12) if compact else (28, 0, 28, 18)
        )
        self.status_frame.configure(
            padding=(16, 7, 16, 9) if compact else (28, 8, 28, 12)
        )

        self.header_left.pack_forget()
        self.header_state_panel.pack_forget()
        if compact:
            self.header_left.pack(fill="x")
            self.header_state_panel.pack(anchor="w", pady=(10, 0))
            self.status_path_label.pack_forget()
            self.footer_progress.configure(length=110)
        else:
            self.header_left.pack(side="left", fill="x", expand=True)
            self.header_state_panel.pack(side="right", anchor="n", pady=2)
            self.status_path_label.pack(side="right")
            self.footer_progress.configure(length=180)

        self._layout_overview(compact)
        self._layout_libraries(compact)
        self._layout_inventory(compact)
        self._layout_automatic(compact)
        self._layout_backup(compact)
        self._layout_restore(compact)
        self._layout_search(compact)
        self._layout_catalog(compact)
        for canvas in self._page_canvases.values():
            canvas.after_idle(lambda target=canvas: target.configure(scrollregion=target.bbox("all")))

    def _layout_overview(self, compact: bool) -> None:
        for cell in self.overview_workflow_cells:
            cell.grid_forget()
        for index, cell in enumerate(self.overview_workflow_cells):
            row, column = (divmod(index, 2) if compact else (0, index))
            cell.grid(
                row=row, column=column, sticky="nsew",
                padx=(0, 8), pady=(0, 10 if compact and row == 0 else 0),
            )
        for column in range(4):
            self.overview_workflow_rail.columnconfigure(column, weight=1 if (not compact or column < 2) else 0)

        for card in self.overview_cards:
            card.grid_forget()
        for index, card in enumerate(self.overview_cards):
            row, column = (divmod(index, 2) if compact else (0, index))
            card.grid(
                row=row, column=column, sticky="nsew",
                padx=(0, 6), pady=(0, 6 if compact and row == 0 else 0),
            )
        for column in range(4):
            self.overview_cards_frame.columnconfigure(column, weight=1 if (not compact or column < 2) else 0)

    def _layout_libraries(self, compact: bool) -> None:
        self.libraries_toolbar_title.pack_forget()
        self.libraries_toolbar_actions.pack_forget()
        for button in self.libraries_toolbar_buttons:
            button.pack_forget()
        if compact:
            self.libraries_toolbar_title.pack(anchor="w", pady=(0, 7))
            self.libraries_toolbar_actions.pack(fill="x")
            for index, button in enumerate(self.libraries_toolbar_buttons):
                button.pack(fill="x", pady=(0 if index == 0 else 5, 0))
        else:
            self.libraries_toolbar_title.pack(side="left")
            self.libraries_toolbar_actions.pack(side="right")
            for index, button in enumerate(self.libraries_toolbar_buttons):
                button.pack(side="left", padx=(0 if index == 0 else 8, 0))

    def _layout_inventory(self, compact: bool) -> None:
        for cell in self.inventory_workflow_cells:
            cell.grid_forget()
        for index, cell in enumerate(self.inventory_workflow_cells):
            cell.grid(
                row=index if compact else 0, column=0 if compact else index, sticky="ew",
                padx=(0, 0 if compact else 12), pady=(0, 8 if compact and index < 2 else 0),
            )
        for column in range(3):
            self.inventory_workflow.columnconfigure(column, weight=1 if (not compact or column == 0) else 0)

        for widget in (
            self.inventory_selection_title, self.inventory_selection_summary_label,
            self.inventory_select_button, self.inventory_calculate_button,
        ):
            widget.grid_forget()
        if compact:
            self.inventory_selection_title.grid(row=0, column=0, columnspan=2, sticky="w")
            self.inventory_selection_summary_label.grid(
                row=1, column=0, columnspan=2, sticky="ew", pady=(7, 9)
            )
            self.inventory_select_button.grid(row=2, column=0, sticky="ew", padx=(0, 5))
            self.inventory_calculate_button.grid(row=2, column=1, sticky="ew", padx=(5, 0))
            self.inventory_selection.columnconfigure(0, weight=1)
            self.inventory_selection.columnconfigure(1, weight=1)
            self.inventory_selection.columnconfigure(2, weight=0)
        else:
            self.inventory_selection_title.grid(row=0, column=0, sticky="w")
            self.inventory_selection_summary_label.grid(row=1, column=0, sticky="ew", pady=(7, 0))
            self.inventory_select_button.grid(
                row=0, column=1, rowspan=2, padx=(14, 8), sticky="e"
            )
            self.inventory_calculate_button.grid(row=0, column=2, rowspan=2, sticky="e")
            self.inventory_selection.columnconfigure(0, weight=1)
            self.inventory_selection.columnconfigure(1, weight=0)

        for card in self.inventory_cards:
            card.grid_forget()
        for index, card in enumerate(self.inventory_cards):
            row, column = (divmod(index, 2) if compact else (0, index))
            card.grid(
                row=row, column=column, sticky="nsew",
                padx=(0, 5), pady=(0, 5 if compact and row == 0 else 0),
            )
        for column in range(4):
            self.inventory_cards_frame.columnconfigure(column, weight=1 if (not compact or column < 2) else 0)

        self.inventory_result_label.pack_forget()
        self.inventory_use_button.pack_forget()
        if compact:
            self.inventory_result_label.pack(fill="x")
            self.inventory_use_button.pack(fill="x", pady=(8, 0))
        else:
            self.inventory_result_label.pack(side="left", fill="x", expand=True)
            self.inventory_use_button.pack(side="right", padx=(12, 0))

    def _layout_automatic(self, compact: bool) -> None:
        self.automatic_form_panel.pack_forget()
        self.automatic_state_panel.pack_forget()
        if compact:
            self.automatic_form_panel.pack(fill="x")
            self.automatic_state_panel.pack(fill="x", pady=(12, 0))
        else:
            self.automatic_form_panel.pack(
                side="left", fill="both", expand=True, padx=(0, 8)
            )
            self.automatic_state_panel.pack(
                side="left", fill="both", expand=True, padx=(8, 0)
            )
        self.automatic_jobs_frame.grid_forget()
        self.automatic_cassette_frame.grid_forget()
        if compact:
            self.automatic_jobs_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
            self.automatic_cassette_frame.grid(row=1, column=0, sticky="nsew")
            self.automatic_panes.columnconfigure(0, weight=1)
            self.automatic_panes.columnconfigure(1, weight=0)
            self.automatic_panes.rowconfigure(0, weight=1)
            self.automatic_panes.rowconfigure(1, weight=2)
        else:
            self.automatic_jobs_frame.grid(row=0, column=0, sticky="nsew")
            self.automatic_cassette_frame.grid(row=0, column=1, sticky="nsew")
            self.automatic_panes.columnconfigure(0, weight=1)
            self.automatic_panes.columnconfigure(1, weight=2)
            self.automatic_panes.rowconfigure(0, weight=1)
            self.automatic_panes.rowconfigure(1, weight=0)

        for cell in self.automatic_timing_cells:
            cell.grid_forget()
        for index, cell in enumerate(self.automatic_timing_cells):
            cell.grid(
                row=index if compact else 0,
                column=0 if compact else index,
                sticky="nsew",
                padx=(0, 0 if compact or index == 2 else 1),
                pady=(0, 1 if compact and index < 2 else 0),
            )
        for column in range(3):
            self.automatic_timing_rail.columnconfigure(
                column,
                weight=1 if (not compact or column == 0) else 0,
                uniform="automatic_timing" if not compact else "",
                minsize=0,
            )

    def _layout_backup(self, compact: bool) -> None:
        widgets = (
            self.backup_form_title, self.backup_library_label, self.backup_library_combo,
            self.backup_tape_label, self.backup_tape_combo, self.backup_mount_label,
            self.backup_mount_entry, self.backup_browse_button, self.backup_actions,
        )
        for widget in widgets:
            widget.grid_forget()
        if compact:
            self.backup_form_title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 14))
            self.backup_library_label.grid(row=1, column=0, sticky="w", pady=(0, 4))
            self.backup_library_combo.grid(row=2, column=0, sticky="ew", padx=(0, 5))
            self.backup_tape_label.grid(row=1, column=1, sticky="w", pady=(0, 4))
            self.backup_tape_combo.grid(row=2, column=1, sticky="ew", padx=(5, 0))
            self.backup_mount_label.grid(row=3, column=0, sticky="w", pady=(12, 4))
            self.backup_mount_entry.grid(row=4, column=0, sticky="ew", padx=(0, 5))
            self.backup_browse_button.grid(row=4, column=1, sticky="ew", padx=(5, 0))
            self.backup_actions.grid(row=5, column=0, columnspan=2, sticky="e", pady=(14, 0))
            self.backup_form.columnconfigure(0, weight=1)
            self.backup_form.columnconfigure(1, weight=1)
            self.backup_form.columnconfigure(2, weight=0)
        else:
            self.backup_form_title.grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 14))
            self.backup_library_label.grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(0, 4))
            self.backup_library_combo.grid(row=2, column=0, sticky="ew", padx=(0, 10))
            self.backup_tape_label.grid(row=1, column=1, sticky="w", padx=(0, 10), pady=(0, 4))
            self.backup_tape_combo.grid(row=2, column=1, sticky="ew", padx=(0, 10))
            self.backup_mount_label.grid(row=1, column=2, sticky="w", padx=(0, 10), pady=(0, 4))
            self.backup_mount_entry.grid(row=2, column=2, sticky="ew", padx=(0, 10))
            self.backup_browse_button.grid(row=2, column=3, padx=(8, 0), sticky="ew")
            self.backup_actions.grid(row=3, column=0, columnspan=4, sticky="e", pady=(18, 0))
            for column, weight in enumerate((2, 2, 1, 0)):
                self.backup_form.columnconfigure(column, weight=weight)

    def _layout_restore(self, compact: bool) -> None:
        widgets = (
            self.restore_form_title, self.restore_library_label, self.restore_library_combo,
            self.restore_tape_label, self.restore_tape_combo, self.restore_mount_label,
            self.restore_mount_entry, self.restore_mount_browse_button,
            self.restore_destination_label, self.restore_destination_entry,
            self.restore_destination_browse_button, self.restore_overwrite_check,
            self.restore_actions,
        )
        for widget in widgets:
            widget.grid_forget()
        if compact:
            self.restore_form_title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 14))
            self.restore_library_label.grid(row=1, column=0, sticky="w", pady=(0, 4))
            self.restore_library_combo.grid(row=2, column=0, sticky="ew", padx=(0, 5))
            self.restore_tape_label.grid(row=1, column=1, sticky="w", pady=(0, 4))
            self.restore_tape_combo.grid(row=2, column=1, sticky="ew", padx=(5, 0))
            self.restore_mount_label.grid(row=3, column=0, sticky="w", pady=(12, 4))
            self.restore_mount_entry.grid(row=4, column=0, sticky="ew", padx=(0, 5))
            self.restore_mount_browse_button.grid(row=4, column=1, sticky="ew", padx=(5, 0))
            self.restore_destination_label.grid(row=5, column=0, columnspan=2, sticky="w", pady=(12, 4))
            self.restore_destination_entry.grid(row=6, column=0, sticky="ew", padx=(0, 5))
            self.restore_destination_browse_button.grid(row=6, column=1, sticky="ew", padx=(5, 0))
            self.restore_overwrite_check.grid(row=7, column=0, columnspan=2, sticky="w", pady=(12, 0))
            self.restore_actions.grid(row=8, column=0, columnspan=2, sticky="e", pady=(12, 0))
            self.restore_form.columnconfigure(0, weight=1)
            self.restore_form.columnconfigure(1, weight=1)
            self.restore_form.columnconfigure(2, weight=0)
        else:
            self.restore_form_title.grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 14))
            self.restore_library_label.grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(0, 4))
            self.restore_library_combo.grid(row=2, column=0, sticky="ew", padx=(0, 10))
            self.restore_tape_label.grid(row=1, column=1, sticky="w", padx=(0, 10), pady=(0, 4))
            self.restore_tape_combo.grid(row=2, column=1, sticky="ew", padx=(0, 10))
            self.restore_mount_label.grid(row=1, column=2, sticky="w", padx=(0, 10), pady=(0, 4))
            self.restore_mount_entry.grid(row=2, column=2, sticky="ew", padx=(0, 10))
            self.restore_mount_browse_button.grid(row=2, column=3, padx=(8, 0))
            self.restore_destination_label.grid(row=3, column=0, sticky="w", pady=(14, 4))
            self.restore_destination_entry.grid(row=4, column=0, columnspan=3, sticky="ew")
            self.restore_destination_browse_button.grid(row=4, column=3, padx=(8, 0))
            self.restore_overwrite_check.grid(row=5, column=0, columnspan=2, sticky="w", pady=(12, 0))
            self.restore_actions.grid(row=5, column=2, columnspan=2, sticky="e", pady=(12, 0))
            for column, weight in enumerate((2, 2, 1, 0)):
                self.restore_form.columnconfigure(column, weight=weight)

    def _layout_search(self, compact: bool) -> None:
        widgets = (
            self.search_panel_title, self.search_panel_description, self.search_query_label,
            self.search_entry, self.search_library_label, self.search_library_combo,
            self.search_button, self.search_tree_button, self.search_history_check,
        )
        for widget in widgets:
            widget.grid_forget()
        if compact:
            self.search_panel_title.grid(row=0, column=0, columnspan=2, sticky="w")
            self.search_panel_description.configure(wraplength=580)
            self.search_panel_description.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))
            self.search_query_label.grid(row=2, column=0, columnspan=2, sticky="w", pady=(12, 4))
            self.search_entry.grid(row=3, column=0, columnspan=2, sticky="ew")
            self.search_library_label.grid(row=4, column=0, sticky="w", pady=(10, 4))
            self.search_library_combo.grid(row=5, column=0, sticky="ew", padx=(0, 5))
            self.search_button.grid(row=5, column=1, sticky="ew", padx=(5, 0))
            self.search_tree_button.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(7, 0))
            self.search_history_check.grid(row=7, column=0, columnspan=2, sticky="w", pady=(12, 0))
            self.search_panel.columnconfigure(0, weight=3)
            self.search_panel.columnconfigure(1, weight=1)
            for column in range(2, 5):
                self.search_panel.columnconfigure(column, weight=0)
        else:
            self.search_panel_title.grid(row=0, column=0, sticky="w")
            self.search_panel_description.configure(wraplength=0)
            self.search_panel_description.grid(row=0, column=1, columnspan=3, sticky="w", padx=(14, 0))
            self.search_query_label.grid(row=1, column=0, sticky="w", pady=(12, 4))
            self.search_entry.grid(row=2, column=0, columnspan=2, sticky="ew", padx=(0, 10))
            self.search_library_label.grid(row=1, column=2, sticky="w", pady=(12, 4))
            self.search_library_combo.grid(row=2, column=2, sticky="ew", padx=(0, 10))
            self.search_button.grid(row=2, column=3)
            self.search_tree_button.grid(row=2, column=4, padx=(8, 0))
            self.search_history_check.grid(row=3, column=0, columnspan=3, sticky="w", pady=(12, 0))
            for column, weight in enumerate((3, 1, 1, 0, 0)):
                self.search_panel.columnconfigure(column, weight=weight)
        self.search_browser.grid_forget()
        self.search_inspector.grid_forget()
        if compact:
            self.search_browser.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
            self.search_inspector.grid(row=1, column=0, sticky="nsew")
            self.search_workspace.columnconfigure(0, weight=1)
            self.search_workspace.columnconfigure(1, weight=0)
            self.search_workspace.rowconfigure(0, weight=3)
            self.search_workspace.rowconfigure(1, weight=2)
        else:
            self.search_browser.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
            self.search_inspector.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
            self.search_workspace.columnconfigure(0, weight=3)
            self.search_workspace.columnconfigure(1, weight=2)
            self.search_workspace.rowconfigure(0, weight=1)
            self.search_workspace.rowconfigure(1, weight=0)

    def _layout_catalog(self, compact: bool) -> None:
        self.catalog_toolbar_title.pack_forget()
        for button in self.catalog_toolbar_buttons:
            button.pack_forget()
        if compact:
            self.catalog_toolbar_title.pack(anchor="w", pady=(0, 7))
            for index, button in enumerate(reversed(self.catalog_toolbar_buttons)):
                button.pack(fill="x", pady=(0 if index == 0 else 5, 0))
        else:
            self.catalog_toolbar_title.pack(side="left")
            for index, button in enumerate(self.catalog_toolbar_buttons):
                button.pack(side="right", padx=(8 if index == 1 else 0))

    def _show_page(self, key: str) -> None:
        page = self._pages.get(key)
        if page is not None:
            page.tkraise()
        self._current_page = key
        metadata = next(item for item in NAVIGATION_ITEMS if item.key == key)
        archive = {
            "it": "ARCHIVIO LTO", "en": "LTO ARCHIVE", "fr": "ARCHIVE LTO",
            "de": "LTO-ARCHIV", "es": "ARCHIVO LTO",
        }.get(self.language, "ARCHIVIO LTO")
        self.page_eyebrow.set(f"{archive} / {self._t(metadata.label).upper()}")
        self.page_title.set(self._t(metadata.title))
        self.page_subtitle.set(self._t(metadata.subtitle))
        for item_key, button in self._nav_buttons.items():
            active = item_key == key
            button.configure(
                bg="#20374a" if active else self.SIDEBAR,
                fg=self.ACCENT if active else ("#d9e2e7" if next(item for item in NAVIGATION_ITEMS if item.key == item_key).marker else self.SIDEBAR_MUTED),
            )

    def _language_changed(self, _event=None) -> None:
        selected = next(
            (code for code, label in LANGUAGES.items() if label == self.language_name.get()),
            self.language,
        )
        if selected == self.language:
            return
        if self._busy:
            self.language_name.set(LANGUAGES[self.language])
            messagebox.showinfo(
                "LTO Archiver",
                "Attendere la fine dell'operazione prima di cambiare lingua.",
                parent=self,
            )
            return
        save_language(self.application.paths.state_dir, selected)
        current_page = self._current_page
        self.language = selected
        self._translator = Translator(selected)
        self._action_buttons.clear()
        self._nav_buttons.clear()
        self._pages.clear()
        self._page_canvases.clear()
        self._responsive_mode = ""
        for child in self.winfo_children():
            child.destroy()
        self._build_shell()
        self._show_page(current_page)
        self._apply_responsive_layout(responsive_mode(self.winfo_width()))
        self.refresh()

    def _build_overview_tab(self) -> None:
        tab = self._new_tab("Panoramica")
        workflow = ttk.Frame(tab, padding=(18, 14), style="Panel.TFrame", relief="solid", borderwidth=1)
        workflow.pack(fill="x", pady=(0, 14))
        ttk.Label(workflow, text="Percorso consigliato", style="Section.TLabel").pack(anchor="w", pady=(0, 10))
        rail = ttk.Frame(workflow, style="Panel.TFrame")
        rail.pack(fill="x")
        self.overview_workflow_rail = rail
        steps = (
            ("01", "Collega", "Aggiungi la libreria SMB", "libraries"),
            ("02", "Pianifica", "Conta file e cassette", "inventory"),
            ("03", "Automatizza", "Inserisci le cassette in sequenza", "automatic"),
            ("04", "Recupera", "Trova e ripristina", "restore"),
        )
        self.overview_workflow = workflow
        self.overview_workflow_cells: list[tk.Frame] = []
        for column, (number, title, detail, key) in enumerate(steps):
            rail.columnconfigure(column, weight=1, uniform="workflow")
            cell = tk.Frame(rail, bg=self.PANEL, cursor="hand2")
            self.overview_workflow_cells.append(cell)
            cell.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 7, 0 if column == 3 else 7))
            marker = tk.Label(cell, text=number, bg=self.ACCENT, fg=self.TEXT, padx=8, pady=4, font=("Cascadia Mono SemiBold", 9))
            marker.pack(anchor="w")
            tk.Label(cell, text=title, bg=self.PANEL, fg=self.TEXT, font=("Segoe UI Variable Display Semibold", 12)).pack(anchor="w", pady=(7, 1))
            tk.Label(cell, text=detail, bg=self.PANEL, fg=self.MUTED, font=("Segoe UI Variable Text", 9)).pack(anchor="w")
            for widget in (cell, marker, *cell.winfo_children()):
                widget.bind("<Button-1>", lambda _event, page=key: self._show_page(page))

        cards = ttk.Frame(tab, style="Panel.TFrame")
        cards.pack(fill="x", pady=(0, 14))
        self.overview_cards_frame = cards
        self.overview_cards: list[ttk.Frame] = []
        self.card_vars: dict[str, tk.StringVar] = {}
        for column, (key, label) in enumerate(
            (("libraries", "LIBRERIE ATTIVE"), ("tapes", "CASSETTE REGISTRATE"), ("blocks", "LOTTI COMPLETATI"), ("reserve", "MARGINE EXTRA"))
        ):
            cards.columnconfigure(column, weight=1, uniform="cards")
            frame = ttk.Frame(cards, padding=(18, 14), style="Panel.TFrame", relief="solid", borderwidth=1)
            self.overview_cards.append(frame)
            frame.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 6, 0 if column == 3 else 6))
            value = tk.StringVar(value="—")
            self.card_vars[key] = value
            ttk.Label(frame, textvariable=value, style="CardValue.TLabel").pack(anchor="w")
            ttk.Label(frame, text=label, style="CardLabel.TLabel").pack(anchor="w", pady=(5, 0))

        recent = ttk.Frame(tab, padding=16, style="Panel.TFrame", relief="solid", borderwidth=1)
        recent.pack(fill="both", expand=True)
        top = ttk.Frame(recent, style="Panel.TFrame")
        top.pack(fill="x", pady=(0, 10))
        ttk.Label(top, text="Attività recente", style="Section.TLabel").pack(side="left")
        self._button(top, "Aggiorna", self.refresh).pack(side="right")
        self.overview_blocks = self._tree(
            recent,
            ("library", "tape", "status", "files", "size", "date"),
            ("Libreria", "Nastro", "Stato", "File", "Dimensione", "Avviato"),
            (120, 120, 100, 75, 110, 170),
        )
        self.overview_blocks.pack(fill="both", expand=True)

    def _build_libraries_tab(self) -> None:
        tab = self._new_tab("Librerie")
        toolbar = ttk.Frame(tab, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, 10))
        self.libraries_toolbar = toolbar
        self.libraries_toolbar_title = ttk.Label(
            toolbar, text="Librerie SMB", style="Section.TLabel"
        )
        self.libraries_toolbar_title.pack(side="left")
        self.libraries_toolbar_actions = ttk.Frame(toolbar, style="Panel.TFrame")
        self.libraries_toolbar_actions.pack(side="right")
        self.verify_unchanged_content = tk.BooleanVar(value=False)
        verification = ttk.Checkbutton(
            self.libraries_toolbar_actions,
            text="Verifica SHA-256 degli invariati",
            variable=self.verify_unchanged_content,
            command=self._toggle_content_verification,
        )
        self.libraries_toolbar_buttons = [
            verification,
            self._button(
                self.libraries_toolbar_actions, "Aggiungi libreria", self._add_library,
                "Accent.TButton",
            ),
            self._button(
                self.libraries_toolbar_actions, "Scansiona tutte", self._scan_all_libraries,
                "Accent.TButton",
            ),
            self._button(self.libraries_toolbar_actions, "Scansiona", self._scan_library),
            self._button(
                self.libraries_toolbar_actions, "Elimina libreria", self._delete_library,
                "Danger.TButton",
            ),
        ]
        for index, button in enumerate(self.libraries_toolbar_buttons):
            button.pack(side="left", padx=(0 if index == 0 else 8, 0))
        self.libraries_tree = self._tree(
            tab,
            ("id", "name", "source", "size", "files", "scanned", "status", "created"),
            ("ID", "Nome", "Sorgente", "Dimensione", "File", "Ultima scansione", "Stato", "Creata"),
            (120, 160, 330, 105, 80, 160, 85, 150),
        )
        self.libraries_tree.pack(fill="both", expand=True)
        self.scan_result_var = tk.StringVar(value="Seleziona una libreria e premi Scansiona.")
        ttk.Label(tab, textvariable=self.scan_result_var, style="Panel.TLabel").pack(fill="x", pady=(12, 0))
        self.library_scan_progress = ttk.Progressbar(tab, maximum=100, mode="determinate")
        self.library_scan_progress.pack(fill="x", pady=(8, 0))

    def _build_inventory_tab(self) -> None:
        tab = self._new_tab("Piano del job")
        workflow = ttk.Frame(tab, padding=(16, 12), style="Panel.TFrame", relief="solid", borderwidth=1)
        workflow.pack(fill="x", pady=(0, 12))
        self.inventory_workflow = workflow
        self.inventory_workflow_cells: list[ttk.Frame] = []
        steps = (
            ("1", "Scegli le librerie", "Il piano considera il job intero"),
            ("2", "Calcola la sequenza", "I file sono combinati per usare meglio lo spazio"),
            ("3", "Prepara il job", "Assegna le etichette e avvia la coda"),
        )
        for column, (number, title, detail) in enumerate(steps):
            workflow.columnconfigure(column, weight=1, uniform="plan_steps")
            cell = ttk.Frame(workflow, style="Panel.TFrame")
            self.inventory_workflow_cells.append(cell)
            cell.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 12, 0))
            tk.Label(
                cell, text=number, bg=self.ACCENT, fg=self.TEXT, padx=8, pady=3,
                font=("Cascadia Mono SemiBold", 9),
            ).pack(side="left", padx=(0, 9))
            copy = ttk.Frame(cell, style="Panel.TFrame")
            copy.pack(side="left", fill="x", expand=True)
            ttk.Label(copy, text=title, style="Section.TLabel").pack(anchor="w")
            ttk.Label(copy, text=detail, style="Utility.TLabel").pack(anchor="w", pady=(2, 0))

        selection = ttk.Frame(tab, padding=14, style="Panel.TFrame", relief="solid", borderwidth=1)
        selection.pack(fill="x", pady=(0, 12))
        self.inventory_selection = selection
        self.inventory_selection_title = ttk.Label(
            selection, text="Librerie incluse nel nuovo job", style="Section.TLabel"
        )
        self.inventory_selection_title.grid(
            row=0, column=0, sticky="w"
        )
        self.inventory_libraries_summary = tk.StringVar(value="Nessuna libreria selezionata")
        self.inventory_selection_summary_label = ttk.Label(
            selection, textvariable=self.inventory_libraries_summary, style="Panel.TLabel",
            wraplength=760,
        )
        self.inventory_selection_summary_label.grid(row=1, column=0, sticky="ew", pady=(7, 0))
        media_picker = ttk.Frame(selection, style="Panel.TFrame")
        media_picker.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(12, 0))
        ttk.Label(media_picker, text="Tipo cassetta", style="Panel.TLabel").pack(side="left")
        self.inventory_media_key = tk.StringVar(value="LTO-6")
        self.inventory_media_combo = ttk.Combobox(
            media_picker,
            textvariable=self.inventory_media_key,
            values=tuple(profile.key for profile in lto_media_profiles()),
            state="readonly",
            width=14,
        )
        self.inventory_media_combo.pack(side="left", padx=(8, 12))
        self.inventory_media_combo.bind(
            "<<ComboboxSelected>>", lambda _event: self._media_selection_changed("inventory")
        )
        self.inventory_media_description = tk.StringVar()
        ttk.Label(
            media_picker,
            textvariable=self.inventory_media_description,
            style="Utility.TLabel",
        ).pack(side="left", fill="x", expand=True)
        self._media_selection_changed("inventory")
        self.inventory_select_button = self._button(
            selection, "Scegli librerie...", self._select_inventory_libraries
        )
        self.inventory_select_button.grid(
            row=0, column=1, rowspan=2, padx=(14, 8), sticky="e"
        )
        self.inventory_calculate_button = self._button(
            selection, "Calcola piano cumulativo", self._analyze_inventory, "Accent.TButton"
        )
        self.inventory_calculate_button.grid(
            row=0, column=2, rowspan=2, sticky="e"
        )
        selection.columnconfigure(0, weight=1)

        summary = ttk.Frame(tab, style="Panel.TFrame")
        summary.pack(fill="x", pady=(0, 12))
        self.inventory_cards_frame = summary
        self.inventory_cards: list[ttk.Frame] = []
        self.inventory_card_vars: dict[str, tk.StringVar] = {}
        for column, (key, label, initial) in enumerate((
            ("libraries", "LIBRERIE NEL JOB", "0"),
            ("pending", "DATI DA COPIARE", "-"),
            ("files", "FILE DA COPIARE", "-"),
            ("tapes", "CASSETTE PREVISTE", "-"),
        )):
            summary.columnconfigure(column, weight=1, uniform="inventory_cards")
            card = ttk.Frame(summary, padding=(16, 12), style="Panel.TFrame", relief="solid", borderwidth=1)
            self.inventory_cards.append(card)
            card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 5, 0))
            value = tk.StringVar(value=initial)
            self.inventory_card_vars[key] = value
            ttk.Label(card, textvariable=value, style="CardValue.TLabel").pack(anchor="w")
            ttk.Label(card, text=label, style="CardLabel.TLabel").pack(anchor="w", pady=(4, 0))

        result_header = ttk.Frame(tab, style="Panel.TFrame")
        result_header.pack(fill="x", pady=(0, 7))
        self.inventory_result_header = result_header
        self.inventory_summary = tk.StringVar(
            value="Scegli una o piu librerie: il calcolo le trattera come un unico job di backup."
        )
        self.inventory_result_label = ttk.Label(
            result_header, textvariable=self.inventory_summary, style="Panel.TLabel", wraplength=900,
        )
        self.inventory_result_label.pack(side="left", fill="x", expand=True)
        self.inventory_use_button = self._button(
            result_header, "Usa questo piano nel job automatico", self._use_inventory_plan,
            "Accent.TButton",
        )
        self.inventory_use_button.configure(state="disabled")
        self.inventory_use_button.pack(side="right", padx=(12, 0))
        self.inventory_reserve_note = tk.StringVar(
            value="Il piano usa 2,41 TB, la capacita dati LTFS documentata per LTO-6, e non divide mai un file."
        )
        ttk.Label(
            tab, textvariable=self.inventory_reserve_note, style="Subtitle.TLabel", wraplength=1080,
        ).pack(fill="x", pady=(0, 9))

        details = ttk.Notebook(tab)
        details.pack(fill="both", expand=True)
        plan = ttk.Frame(details, padding=8, style="Panel.TFrame")
        distribution = ttk.Frame(details, padding=8, style="Panel.TFrame")
        libraries = ttk.Frame(details, padding=8, style="Panel.TFrame")
        capacities = ttk.Frame(details, padding=8, style="Panel.TFrame")
        details.add(plan, text="Sequenza cassette")
        details.add(distribution, text="Ripartizione per libreria")
        details.add(libraries, text="Riepilogo librerie")
        details.add(capacities, text="Capacita LTO")
        self.inventory_plan_tree = self._tree(
            plan,
            ("slot", "mix", "files", "size", "usage", "free"),
            ("Sequenza", "Librerie contenute", "File", "Dati", "Riempimento", "Spazio residuo stimato"),
            (95, 360, 80, 120, 120, 175),
        )
        self.inventory_plan_tree.pack(fill="both", expand=True)
        self.inventory_distribution_tree = self._tree(
            distribution,
            ("slot", "library", "files", "size", "share"),
            ("Cassetta", "Libreria", "File", "Dati", "Quota della cassetta"),
            (110, 260, 100, 150, 160),
        )
        self.inventory_distribution_tree.pack(fill="both", expand=True)
        self.inventory_libraries_tree = self._tree(
            libraries,
            ("library", "name", "total", "pending", "archived", "recent"),
            ("Libreria", "Nome", "Contenuto totale", "Da copiare", "Gia catalogati", "Troppo recenti"),
            (130, 210, 180, 180, 120, 120),
        )
        self.inventory_libraries_tree.pack(fill="both", expand=True)
        self.inventory_capacities_tree = self._tree(
            capacities,
            ("media", "native", "ltfs", "compressed", "suffix", "notes"),
            ("Tipo", "Nativa", "Utilizzabile LTFS", "Compressa teorica", "Barcode", "Note"),
            (120, 110, 150, 150, 90, 270),
        )
        self.inventory_capacities_tree.pack(fill="both", expand=True)
        self._replace_tree(
            self.inventory_capacities_tree,
            (
                (row["media_key"], row["native"], row["ltfs"], row["compressed"],
                 row["barcode_suffix"], row["notes"])
                for row in lto_capacity_rows()
            ),
        )

    def _build_automatic_tab(self) -> None:
        tab = self._new_tab("Job automatici")
        top = ttk.Frame(tab, style="Panel.TFrame")
        top.pack(fill="x")
        self.automatic_top = top

        form = ttk.Frame(top, padding=16, style="Panel.TFrame", relief="solid", borderwidth=1)
        form.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.automatic_form_panel = form
        ttk.Label(form, text="Crea un nuovo job salvato", style="Section.TLabel").grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 12)
        )
        self.automatic_libraries_summary = tk.StringVar(
            value=self._t("Nessuna libreria selezionata")
        )
        self.automatic_device = tk.StringVar(value="TAPE0")
        self.automatic_mount = tk.StringVar(value="AUTO")
        self.automatic_media_key = tk.StringVar(value="LTO-6")
        ttk.Label(form, text="Librerie cumulative", style="Panel.TLabel").grid(
            row=1, column=0, sticky="w", padx=(0, 10), pady=(0, 4)
        )
        library_picker = ttk.Frame(form, style="Panel.TFrame")
        library_picker.grid(row=2, column=0, sticky="ew", padx=(0, 10))
        ttk.Entry(
            library_picker,
            textvariable=self.automatic_libraries_summary,
            state="readonly",
        ).pack(side="left", fill="x", expand=True)
        self._button(
            library_picker, "Seleziona...", self._select_automatic_libraries
        ).pack(side="left", padx=(7, 0))
        self._labeled_entry(form, 1, 1, "Drive", self.automatic_device, width=12)
        ttk.Label(form, text="Tipo cassetta", style="Panel.TLabel").grid(
            row=1, column=2, sticky="w", pady=(0, 4)
        )
        self.automatic_media_combo = ttk.Combobox(
            form,
            textvariable=self.automatic_media_key,
            values=tuple(profile.key for profile in lto_media_profiles()),
            state="readonly",
            width=15,
        )
        self.automatic_media_combo.grid(row=2, column=2, sticky="ew")
        self.automatic_media_combo.bind(
            "<<ComboboxSelected>>", lambda _event: self._media_selection_changed("automatic")
        )
        self.automatic_plan_hint = tk.StringVar(value=self._t(
            "Prima calcola il Piano cassette, oppure seleziona qui le librerie del job."
        ))
        ttk.Label(
            form, textvariable=self.automatic_plan_hint, style="Utility.TLabel", wraplength=720,
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(10, 0))
        self.automatic_labels_hint = tk.StringVar()
        ttk.Label(
            form,
            textvariable=self.automatic_labels_hint,
            style="Panel.TLabel",
        ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(12, 4))
        self._media_selection_changed("automatic")
        self.automatic_labels = tk.Text(
            form, height=5, relief="solid", borderwidth=1, bg="#ffffff", fg=self.TEXT,
            font=("Cascadia Mono", 10), padx=8, pady=7,
        )
        self.automatic_labels.grid(row=5, column=0, columnspan=3, sticky="nsew")
        self.automatic_confirm = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            form,
            text="Confermo: ogni cassetta inserita sara riformattata LTFS e tutti i dati presenti saranno cancellati.",
            variable=self.automatic_confirm,
        ).grid(row=6, column=0, columnspan=3, sticky="w", pady=(10, 0))
        self.automatic_reuse_registered = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            form,
            text=self._t(
                "Consento anche di riformattare cassette gia registrate: dopo la formattazione "
                "i relativi file e blocchi saranno rimossi dal catalogo."
            ),
            variable=self.automatic_reuse_registered,
        ).grid(row=7, column=0, columnspan=3, sticky="w", pady=(7, 0))
        ttk.Label(
            form,
            text="Il drive non legge l'etichetta adesiva: inserire sempre la cassetta fisica richiesta. "
                 "Sono accettati supporti nuovi o gia LTFS; le cassette gia catalogate restano "
                 "protette salvo autorizzazione esplicita.",
            foreground=self.DANGER,
            background=self.PANEL,
            wraplength=720,
        ).grid(row=8, column=0, columnspan=3, sticky="w", pady=(7, 0))
        actions = ttk.Frame(form, style="Panel.TFrame")
        actions.grid(row=9, column=0, columnspan=3, sticky="e", pady=(14, 0))
        self._button(
            actions, self._t("Salva job"), self._create_automatic_job, "Accent.TButton"
        ).pack(side="left")
        form.columnconfigure(0, weight=2)
        form.columnconfigure(1, weight=1)
        form.columnconfigure(2, weight=1)

        state = ttk.Frame(top, padding=16, style="Panel.TFrame", relief="solid", borderwidth=1)
        state.pack(side="left", fill="both", expand=True, padx=(8, 0))
        self.automatic_state_panel = state
        ttk.Label(state, text="Continuita del job", style="Section.TLabel").pack(anchor="w")
        ttk.Label(
            state,
            text=self._t(
                "Puoi salvare piu job indipendenti, ma non esiste un avvio FIFO automatico. "
                "Il drive esegue soltanto il job che selezioni e avvii esplicitamente."
            ),
            style="Panel.TLabel",
            wraplength=440,
        ).pack(anchor="w", fill="x", pady=(7, 8))
        continuity = ttk.Frame(state, style="Panel.TFrame")
        continuity.pack(fill="x", pady=(0, 10))
        for marker, title, detail in (
            ("1", self._t("SALVA"), self._t("Il piano resta nel catalogo senza avviare il drive")),
            ("2", self._t("AVVIA"), self._t("Parte solo il job selezionato dall'operatore")),
            ("3", self._t("CHECKPOINT"), self._t("Riprende dal primo supporto non completato")),
        ):
            row = ttk.Frame(continuity, style="Panel.TFrame")
            row.pack(fill="x", pady=2)
            tk.Label(
                row, text=marker, width=2, bg=self.ACCENT, fg="#ffffff",
                font=("Cascadia Mono SemiBold", 9),
            ).pack(side="left", padx=(0, 8))
            ttk.Label(row, text=title, style="CardLabel.TLabel", width=12).pack(side="left")
            ttk.Label(
                row, text=detail, style="Utility.TLabel", wraplength=300,
            ).pack(side="left", fill="x", expand=True)
        self.automatic_state = tk.StringVar(value=self._t("Nessun job in esecuzione."))
        self.automatic_state_field = stable_status_field(
            state,
            self.automatic_state,
            height=44,
            background=self.PANEL,
            foreground=self.TEXT,
            font=("Segoe UI Variable Text", 10),
            wraplength=420,
        )
        self.automatic_state_field.pack(fill="x", pady=(10, 12))
        self.automatic_write_speed = tk.StringVar(
            value=write_speed_text(None, 0.0, language=self.language)
        )
        self.automatic_speed_field = stable_status_field(
            state,
            self.automatic_write_speed,
            height=34,
            background=self.PANEL,
            foreground=self.MUTED,
            font=("Segoe UI Variable Text Semibold", 8),
            wraplength=440,
        )
        self.automatic_speed_field.pack(fill="x", pady=(0, 5))
        self.automatic_speed_chart = WriteSpeedChart(state, language=self.language)
        self.automatic_speed_chart.pack(fill="x", pady=(2, 8))
        initial_timing = write_timing_view({}, language=self.language)
        self.automatic_elapsed_time = tk.StringVar(value=initial_timing["elapsed"])
        self.automatic_tape_eta = tk.StringVar(value=initial_timing["tape_eta"])
        self.automatic_job_eta = tk.StringVar(value=initial_timing["job_eta"])
        self.automatic_timing_rail = tk.Frame(
            state, bg="#435465", highlightthickness=0, borderwidth=0
        )
        self.automatic_timing_rail.pack(fill="x", pady=(7, 10))
        self.automatic_timing_cells: list[tk.Frame] = []
        for label, value in (
            (initial_timing["elapsed_label"], self.automatic_elapsed_time),
            (initial_timing["tape_eta_label"], self.automatic_tape_eta),
            (initial_timing["job_eta_label"], self.automatic_job_eta),
        ):
            cell = stable_metric_cell(
                self.automatic_timing_rail,
                label,
                value,
                background=self.SIDEBAR,
                foreground="#ffffff",
                accent=self.ACCENT,
            )
            self.automatic_timing_cells.append(cell)
        for column in range(3):
            self.automatic_timing_rail.columnconfigure(
                column, weight=1, uniform="automatic_timing"
            )
        self.automatic_ltfs_activity = tk.StringVar(
            value=self._t("Telemetria LTFS: in attesa")
        )
        self.automatic_ltfs_field = stable_status_field(
            state,
            self.automatic_ltfs_activity,
            height=32,
            background=self.PANEL,
            foreground=self.MUTED,
            font=("Cascadia Mono", 8),
            wraplength=440,
        )
        self.automatic_ltfs_field.pack(fill="x", pady=(0, 10))
        finalize_console = tk.Frame(
            state,
            height=166,
            bg="#e8eef1",
            padx=12,
            pady=9,
            highlightthickness=0,
            borderwidth=0,
        )
        finalize_console.pack(fill="x", pady=(0, 12))
        finalize_console.pack_propagate(False)
        self.automatic_finalize_panel = finalize_console
        tk.Frame(finalize_console, bg=self.ACCENT, width=4).place(
            x=0, y=0, relheight=1
        )
        tk.Label(
            finalize_console,
            text=self._t("FINALIZZAZIONE CASSETTA LTFS"),
            bg="#e8eef1",
            fg=self.MUTED,
            font=("Cascadia Mono SemiBold", 8),
            anchor="w",
        ).pack(fill="x")
        self.automatic_finalize_phase = tk.StringVar(value=self._t("Inattivo"))
        self.automatic_finalize_detail = tk.StringVar(
            value=self._t("Nessuna finalizzazione in corso")
        )
        self.automatic_finalize_phase_field = stable_status_field(
            finalize_console,
            self.automatic_finalize_phase,
            height=22,
            background="#e8eef1",
            foreground=self.TEXT,
            font=("Segoe UI Variable Text Semibold", 9),
        )
        self.automatic_finalize_phase_field.pack(fill="x", pady=(3, 0))
        self.automatic_finalize_detail_field = stable_status_field(
            finalize_console,
            self.automatic_finalize_detail,
            height=18,
            background="#e8eef1",
            foreground=self.MUTED,
            font=("Cascadia Mono", 7),
        )
        self.automatic_finalize_detail_field.pack(fill="x")
        self.automatic_finalize_progress = ttk.Progressbar(
            finalize_console, maximum=100, mode="determinate"
        )
        self.automatic_finalize_progress.pack(fill="x", pady=(4, 6))
        self.automatic_finalize_counter = tk.StringVar(value="-")
        self.automatic_finalize_elapsed = tk.StringVar(value="-")
        self.automatic_finalize_eta = tk.StringVar(value="-")
        self.automatic_finalize_metrics = tk.Frame(
            finalize_console, bg=self.SIDEBAR, highlightthickness=0, borderwidth=0
        )
        self.automatic_finalize_metrics.pack(fill="x")
        self.automatic_finalize_cells: list[tk.Frame] = []
        for column, (label, value) in enumerate((
            (self._t("AVANZAMENTO"), self.automatic_finalize_counter),
            (self._t("TRASCORSO FASE"), self.automatic_finalize_elapsed),
            (self._t("ETA FASE"), self.automatic_finalize_eta),
        )):
            cell = stable_metric_cell(
                self.automatic_finalize_metrics,
                label,
                value,
                background=self.SIDEBAR,
                foreground="#ffffff",
                accent=self.ACCENT,
                height=54,
            )
            cell.grid(
                row=0, column=column, sticky="nsew",
                padx=(0, 0 if column == 2 else 1),
            )
            self.automatic_finalize_cells.append(cell)
            self.automatic_finalize_metrics.columnconfigure(
                column, weight=1, uniform="automatic_finalize"
            )
        self._set_automatic_finalization_active(False)
        tape_console = ttk.Frame(state, style="Panel.TFrame")
        tape_console.pack(fill="x", pady=(0, 12))
        self.automatic_tape_capacity_title = tk.StringVar(value=self._t(
            "CASSETTA CORRENTE  |  capacita disponibile dopo il mount"
        ))
        self.automatic_tape_capacity_title_field = stable_status_field(
            tape_console,
            self.automatic_tape_capacity_title,
            height=22,
            background=self.PANEL,
            foreground=self.TEXT,
            font=("Cascadia Mono SemiBold", 8),
        )
        self.automatic_tape_capacity_title_field.pack(fill="x")
        self.automatic_tape_capacity_progress = ttk.Progressbar(
            tape_console, maximum=100, mode="determinate"
        )
        self.automatic_tape_capacity_progress.pack(fill="x", pady=(6, 5))
        self.automatic_tape_remaining = tk.StringVar(
            value=self._t("Disponibile per la scrittura: -")
        )
        self.automatic_tape_ltfs_free = tk.StringVar(
            value=self._t("Libero rilevato da LTFS: -")
        )
        self.automatic_tape_policy = tk.StringVar(value=self._t(
            "Limite applicativo: -  |  Margine operativo: -"
        ))
        self.automatic_tape_remaining_field = stable_status_field(
            tape_console,
            self.automatic_tape_remaining,
            height=22,
            background=self.PANEL,
            foreground=self.TEXT,
            font=("Segoe UI Variable Text", 9),
        )
        self.automatic_tape_remaining_field.pack(fill="x")
        self.automatic_tape_ltfs_free_field = stable_status_field(
            tape_console,
            self.automatic_tape_ltfs_free,
            height=20,
            background=self.PANEL,
            foreground=self.MUTED,
            font=("Segoe UI Variable Text", 8),
        )
        self.automatic_tape_ltfs_free_field.pack(fill="x", pady=(2, 0))
        self.automatic_tape_policy_field = stable_status_field(
            tape_console,
            self.automatic_tape_policy,
            height=20,
            background=self.PANEL,
            foreground=self.MUTED,
            font=("Segoe UI Variable Text", 8),
        )
        self.automatic_tape_policy_field.pack(fill="x", pady=(2, 0))
        buttons = ttk.Frame(state, style="Panel.TFrame")
        buttons.pack(anchor="w", fill="x")
        ttk.Label(
            buttons, text="AZIONI SUL JOB SELEZIONATO", style="CardLabel.TLabel"
        ).pack(anchor="w", pady=(0, 5))
        self._button(
            buttons,
            self._t("Avvia / riprendi job selezionato"),
            self._continue_automatic_job,
            "Accent.TButton",
        ).pack(fill="x")
        self._button(
            buttons,
            "Rinomina job",
            self._rename_automatic_job,
        ).pack(fill="x", pady=(6, 0))
        self._button(
            buttons,
            self._t("Elimina job"),
            self._delete_automatic_job,
            "Danger.TButton",
        ).pack(fill="x", pady=(6, 0))
        self.automatic_retry_button = self._button(
            buttons,
            self._t("Reimposta e riprova cassetta"),
            self._retry_failed_automatic_cassette,
            "Danger.TButton",
        )
        self.automatic_retry_button.configure(state="disabled")
        self.automatic_retry_button.pack(fill="x", pady=(6, 0))
        ttk.Label(
            buttons,
            text=self._t(
                "Lascia vuoto il riquadro etichette per avviare o riprendere. "
                "Se inserisci etichette, vengono aggiunte allo stesso job prima dell'avvio."
            ),
            style="Utility.TLabel",
            wraplength=410,
        ).pack(anchor="w", fill="x", pady=(6, 0))
        self.automatic_stop_button = ttk.Button(
            buttons, text="Interrompi ora", command=self._stop_automatic_job,
            style="Danger.TButton", state="disabled",
        )
        self.automatic_stop_button.pack(fill="x", pady=(6, 0))
        ttk.Label(
            state,
            text="Interrompi ora ferma la copia al prossimo buffer, chiude LTFS e la espelle. "
                 "Una cassetta NUOVA riparte con formattazione da zero; una cassetta APPEND conserva "
                 "i blocchi precedenti e riprova soltanto il nuovo ciclo.",
            style="Subtitle.TLabel",
            wraplength=440,
        ).pack(anchor="w", fill="x", pady=(14, 0))

        queue_panel = ttk.Frame(tab, padding=14, style="Panel.TFrame", relief="solid", borderwidth=1)
        queue_panel.pack(fill="both", expand=True, pady=(16, 0))
        queue_header = ttk.Frame(queue_panel, style="Panel.TFrame")
        queue_header.pack(fill="x", pady=(0, 9))
        self.automatic_queue_title = ttk.Label(
            queue_header, text="Job salvati e checkpoint cassette", style="Section.TLabel"
        )
        self.automatic_queue_title.grid(row=0, column=0, sticky="w")
        self.automatic_jobs_catalog_summary = tk.StringVar(
            value="0 job salvati | seleziona il job da gestire"
        )
        self.automatic_queue_summary_label = ttk.Label(
            queue_header,
            textvariable=self.automatic_jobs_catalog_summary,
            style="Utility.TLabel",
        )
        self.automatic_queue_summary_label.grid(row=1, column=0, sticky="w", pady=(3, 0))
        queue_header.columnconfigure(0, weight=1)

        selected = tk.Frame(queue_panel, bg=self.SIDEBAR, padx=16, pady=12)
        selected.pack(fill="x", pady=(0, 10))
        for column in range(4):
            selected.columnconfigure(column, weight=1, uniform="automatic_summary")
        self.automatic_selected_job_title = tk.StringVar(value="NESSUN JOB SELEZIONATO")
        self.automatic_selected_job_detail = tk.StringVar(
            value="Nessun job salvato. Il primo job creato restera disponibile dopo la chiusura."
        )
        self.automatic_selected_job_checkpoint = tk.StringVar(value="CATALOGO PRONTO")
        self.automatic_selected_job_action = tk.StringVar(value="In attesa di una pianificazione")
        tk.Label(
            selected, textvariable=self.automatic_selected_job_title, bg=self.SIDEBAR,
            fg="#ffffff", anchor="w", font=("Cascadia Mono SemiBold", 10),
        ).grid(row=0, column=0, columnspan=4, sticky="w")
        tk.Label(
            selected, textvariable=self.automatic_selected_job_detail, bg=self.SIDEBAR,
            fg=self.SIDEBAR_MUTED, anchor="w", font=("Segoe UI Variable Text", 9),
        ).grid(row=1, column=0, columnspan=4, sticky="w", pady=(3, 0))
        tk.Label(
            selected, textvariable=self.automatic_selected_job_checkpoint, bg=self.SIDEBAR,
            fg=self.ACCENT, anchor="w", font=("Cascadia Mono SemiBold", 9),
        ).grid(row=2, column=0, columnspan=4, sticky="w", pady=(7, 0))
        self.automatic_selected_action_field = stable_status_field(
            selected,
            self.automatic_selected_job_action,
            height=28,
            background=self.SIDEBAR,
            foreground="#ffffff",
            font=("Segoe UI Variable Text Semibold", 10),
        )
        self.automatic_selected_action_field.grid(
            row=3, column=0, columnspan=4, sticky="ew", pady=(4, 0)
        )
        self.automatic_summary_vars: dict[str, tk.StringVar] = {}
        for column, (key, label) in enumerate((
            ("status", "STATO"),
            ("cassettes", "CASSETTE"),
            ("planned", "DATI PREVISTI"),
            ("copied", "DATI COPIATI"),
        )):
            value = tk.StringVar(value="-")
            self.automatic_summary_vars[key] = value
            metric = tk.Frame(selected, bg=self.SIDEBAR, padx=10)
            metric.grid(row=4, column=column, sticky="nsew", pady=(10, 0))
            tk.Label(
                metric, textvariable=value, bg=self.SIDEBAR, fg="#ffffff",
                font=("Cascadia Mono SemiBold", 14),
            ).pack(anchor="w", pady=(3, 0))
            tk.Label(
                metric, text=label, bg=self.SIDEBAR, fg=self.SIDEBAR_MUTED,
                font=("Cascadia Mono SemiBold", 8),
            ).pack(anchor="w", pady=(3, 0))
        self.automatic_job_progress = ttk.Progressbar(
            queue_panel, maximum=100, mode="determinate"
        )
        self.automatic_job_progress.pack(fill="x", pady=(0, 11))

        panes = ttk.Frame(queue_panel, style="Panel.TFrame")
        panes.pack(fill="both", expand=True)
        self.automatic_panes = panes
        jobs_frame = ttk.Frame(panes, padding=(0, 0, 8, 0), style="Panel.TFrame")
        cassette_frame = ttk.Frame(panes, padding=(8, 0, 0, 0), style="Panel.TFrame")
        self.automatic_jobs_frame = jobs_frame
        self.automatic_cassette_frame = cassette_frame
        jobs_frame.grid(row=0, column=0, sticky="nsew")
        cassette_frame.grid(row=0, column=1, sticky="nsew")
        panes.columnconfigure(0, weight=1)
        panes.columnconfigure(1, weight=2)
        panes.rowconfigure(0, weight=1)
        ttk.Label(
            jobs_frame, text="JOB SALVATI - SELEZIONA QUELLO DA GESTIRE", style="CardLabel.TLabel"
        ).pack(
            anchor="w", pady=(0, 6)
        )
        self.automatic_jobs_tree = self._tree(
            jobs_frame,
            ("id", "library", "status", "progress", "next", "created"),
            ("Nome job", "Librerie", "Stato", "Checkpoint", "Prossima", "Creato"),
            (180, 170, 110, 105, 115, 150),
        )
        self.automatic_jobs_tree.pack(fill="both", expand=True)
        self.automatic_jobs_tree.bind("<<TreeviewSelect>>", self._automatic_job_selected)
        self.automatic_jobs_tree.tag_configure(
            "job_completed", background="#e7f1f0", foreground=self.TEXT
        )
        self.automatic_jobs_tree.tag_configure(
            "job_active", background="#fff6e8", foreground=self.TEXT
        )
        self.automatic_jobs_tree.tag_configure(
            "job_failed", background="#f8dddd", foreground=self.DANGER
        )
        cassette_title = ttk.Frame(cassette_frame, style="Panel.TFrame")
        cassette_title.pack(fill="x", pady=(0, 6))
        ttk.Label(cassette_title, text="PERCORSO CASSETTE", style="CardLabel.TLabel").pack(side="left")
        ttk.Label(
            cassette_title,
            text="[OK] conclusa   [ORA] intervento richiesto   [ ] successiva   [R] riserva",
            style="Utility.TLabel",
        ).pack(side="right")
        self.automatic_queue_tree = self._tree(
            cassette_frame,
            ("step", "label", "operation", "status", "files", "planned", "copied", "block"),
            ("Passo", "Etichetta fisica", "Operazione", "Stato operativo", "File", "Previsti", "Copiati", "Blocco"),
            (105, 135, 165, 150, 75, 110, 110, 175),
        )
        self.automatic_queue_tree.pack(fill="both", expand=True)
        self.automatic_queue_tree.tag_configure(
            "queue_done", background="#dcebea", foreground=self.TEXT
        )
        self.automatic_queue_tree.tag_configure(
            "queue_current", background="#fff0d5", foreground=self.TEXT
        )
        self.automatic_queue_tree.tag_configure(
            "queue_failed", background="#f8dddd", foreground=self.DANGER
        )
        self.automatic_queue_tree.tag_configure(
            "queue_pending", background="#fcfdfd", foreground=self.MUTED
        )
        self.automatic_queue_tree.tag_configure(
            "queue_reserved", background="#eef4fb", foreground="#46627f"
        )

    def _build_backup_tab(self) -> None:
        tab = self._new_tab("Backup")
        form = ttk.Frame(tab, padding=18, style="Panel.TFrame", relief="solid", borderwidth=1)
        form.pack(fill="x")
        self.backup_form = form
        self.backup_form_title = ttk.Label(
            form, text="Nuovo blocco di backup", style="Section.TLabel"
        )
        self.backup_form_title.grid(
            row=0, column=0, columnspan=4, sticky="w", pady=(0, 14)
        )
        self.backup_library = tk.StringVar()
        self.backup_tape = tk.StringVar()
        self.backup_mount = tk.StringVar(value="L:\\")
        self._labeled_combo(form, 1, 0, "Libreria", self.backup_library)
        self.backup_library_combo = form.grid_slaves(row=2, column=0)[0]
        self.backup_library_label = form.grid_slaves(row=1, column=0)[0]
        self._labeled_combo(form, 1, 1, "Nastro", self.backup_tape)
        self.backup_tape_combo = form.grid_slaves(row=2, column=1)[0]
        self.backup_tape_label = form.grid_slaves(row=1, column=1)[0]
        self._labeled_entry(form, 1, 2, "Mount LTFS", self.backup_mount, width=18)
        self.backup_mount_label = form.grid_slaves(row=1, column=2)[0]
        self.backup_mount_entry = form.grid_slaves(row=2, column=2)[0]
        self._button(form, "Sfoglia…", lambda: self._browse_to(self.backup_mount)).grid(row=2, column=3, padx=(8, 0), sticky="ew")
        self.backup_browse_button = form.grid_slaves(row=2, column=3)[0]
        self.backup_tape_combo.bind("<<ComboboxSelected>>", self._tape_selected)
        form.columnconfigure(0, weight=2)
        form.columnconfigure(1, weight=2)
        form.columnconfigure(2, weight=1)
        actions = ttk.Frame(form, style="Panel.TFrame")
        actions.grid(row=3, column=0, columnspan=4, sticky="e", pady=(18, 0))
        self.backup_actions = actions
        self._button(actions, "Registra nastro montato", self._register_tape).pack(side="left")
        self._button(actions, "Verifica", self._doctor_backup).pack(side="left", padx=8)
        self._button(actions, "Avvia backup", self._start_backup, "Accent.TButton").pack(side="left")

        progress = ttk.Frame(tab, padding=18, style="Panel.TFrame", relief="solid", borderwidth=1)
        progress.pack(fill="both", expand=True, pady=(16, 0))
        self.operation_var = tk.StringVar(value="Pronto. La scrittura usa lo spazio libero reale comunicato dal volume LTFS.")
        ttk.Label(progress, textvariable=self.operation_var, style="Section.TLabel", wraplength=900).pack(anchor="w")
        self.progress_bar = ttk.Progressbar(progress, maximum=100, mode="determinate")
        self.progress_bar.pack(fill="x", pady=(14, 14))
        self.log_text = tk.Text(
            progress,
            height=12,
            relief="flat",
            bg="#f8fafc",
            fg=self.TEXT,
            font=("Consolas", 9),
            wrap="word",
            state="disabled",
        )
        self.log_text.pack(fill="both", expand=True)

    def _build_restore_tab(self) -> None:
        tab = self._new_tab("Ripristino")
        form = ttk.Frame(tab, padding=18, style="Panel.TFrame", relief="solid", borderwidth=1)
        form.pack(fill="x")
        self.restore_form = form
        self.restore_form_title = ttk.Label(
            form, text="Ripristina una libreria", style="Section.TLabel"
        )
        self.restore_form_title.grid(
            row=0, column=0, columnspan=4, sticky="w", pady=(0, 14)
        )
        self.restore_library = tk.StringVar()
        self.restore_tape = tk.StringVar()
        self.restore_mount = tk.StringVar(value="L:\\")
        self.restore_destination = tk.StringVar()
        self.restore_overwrite = tk.BooleanVar(value=False)
        self._labeled_combo(form, 1, 0, "Libreria", self.restore_library)
        self.restore_library_combo = form.grid_slaves(row=2, column=0)[0]
        self.restore_library_label = form.grid_slaves(row=1, column=0)[0]
        self._labeled_combo(form, 1, 1, "Nastro", self.restore_tape)
        self.restore_tape_combo = form.grid_slaves(row=2, column=1)[0]
        self.restore_tape_label = form.grid_slaves(row=1, column=1)[0]
        self._labeled_entry(form, 1, 2, "Mount LTFS", self.restore_mount, width=18)
        self.restore_mount_label = form.grid_slaves(row=1, column=2)[0]
        self.restore_mount_entry = form.grid_slaves(row=2, column=2)[0]
        self._button(form, "Sfoglia…", lambda: self._browse_to(self.restore_mount)).grid(row=2, column=3, padx=(8, 0))
        self.restore_mount_browse_button = form.grid_slaves(row=2, column=3)[0]
        self.restore_tape_combo.bind("<<ComboboxSelected>>", self._restore_tape_selected)
        ttk.Label(form, text="Destinazione", style="Panel.TLabel").grid(row=3, column=0, sticky="w", pady=(14, 4))
        ttk.Entry(form, textvariable=self.restore_destination).grid(row=4, column=0, columnspan=3, sticky="ew")
        self._button(form, "Sfoglia…", lambda: self._browse_to(self.restore_destination)).grid(row=4, column=3, padx=(8, 0))
        ttk.Checkbutton(form, text="Sovrascrivi file diversi già presenti", variable=self.restore_overwrite).grid(row=5, column=0, columnspan=2, sticky="w", pady=(12, 0))
        self.restore_destination_label = form.grid_slaves(row=3, column=0)[0]
        self.restore_destination_entry = form.grid_slaves(row=4, column=0)[0]
        self.restore_destination_browse_button = form.grid_slaves(row=4, column=3)[0]
        self.restore_overwrite_check = form.grid_slaves(row=5, column=0)[0]
        actions = ttk.Frame(form, style="Panel.TFrame")
        actions.grid(row=5, column=2, columnspan=2, sticky="e", pady=(12, 0))
        self.restore_actions = actions
        self._button(actions, "Mostra piano", self._restore_plan).pack(side="left", padx=(0, 8))
        self._button(actions, "Ripristina nastro", self._start_restore, "Accent.TButton").pack(side="left")
        form.columnconfigure(0, weight=2)
        form.columnconfigure(1, weight=2)
        form.columnconfigure(2, weight=1)

        result = ttk.Frame(tab, padding=16, style="Panel.TFrame", relief="solid", borderwidth=1)
        result.pack(fill="both", expand=True, pady=(16, 0))
        ttk.Label(result, text="Nastri richiesti", style="Section.TLabel").pack(anchor="w", pady=(0, 10))
        self.restore_plan_tree = self._tree(
            result,
            ("order", "tape", "files", "size"),
            ("Ordine", "Nastro", "File correnti", "Dimensione"),
            (80, 180, 130, 150),
        )
        self.restore_plan_tree.pack(fill="both", expand=True)

    def _build_search_tab(self) -> None:
        tab = self._new_tab("Ricerca file")
        search_panel = ttk.Frame(tab, padding=(16, 13), style="Panel.TFrame", relief="solid", borderwidth=1)
        search_panel.pack(fill="x")
        self.search_panel = search_panel
        self.search_panel_title = ttk.Label(
            search_panel, text="Catalogo locale  /  OFFLINE", style="Section.TLabel"
        )
        self.search_panel_title.grid(
            row=0, column=0, sticky="w"
        )
        self.search_panel_description = ttk.Label(
            search_panel,
            text="Struttura e posizioni sono disponibili senza inserire alcuna cassetta.",
            style="Panel.TLabel",
        )
        self.search_panel_description.grid(
            row=0, column=1, columnspan=3, sticky="w", padx=(14, 0)
        )
        self.search_query = tk.StringVar()
        self.search_library = tk.StringVar(value="Tutte")
        self.search_history = tk.BooleanVar(value=False)
        self.search_query_label = ttk.Label(
            search_panel, text="Nome o parte del percorso", style="Panel.TLabel"
        )
        self.search_query_label.grid(
            row=1, column=0, sticky="w", pady=(12, 4)
        )
        search_entry = ttk.Entry(search_panel, textvariable=self.search_query)
        self.search_entry = search_entry
        search_entry.grid(row=2, column=0, columnspan=2, sticky="ew", padx=(0, 10))
        search_entry.bind("<Return>", lambda _event: self._search_files())
        self.search_library_label = ttk.Label(search_panel, text="Libreria", style="Panel.TLabel")
        self.search_library_label.grid(
            row=1, column=2, sticky="w", pady=(12, 4)
        )
        self.search_library_combo = ttk.Combobox(
            search_panel,
            textvariable=self.search_library,
            state="readonly",
            width=20,
        )
        self.search_library_combo.grid(row=2, column=2, sticky="ew", padx=(0, 10))
        self.search_button = self._button(
            search_panel, "Cerca", self._search_files, "Accent.TButton"
        )
        self.search_button.grid(row=2, column=3)
        self.search_tree_button = self._button(
            search_panel, "Mostra albero", self._reset_backup_explorer
        )
        self.search_tree_button.grid(
            row=2, column=4, padx=(8, 0)
        )
        self.search_history_check = ttk.Checkbutton(
            search_panel,
            text="Includi versioni storiche e record rimossi logicamente",
            variable=self.search_history,
        )
        self.search_history_check.grid(
            row=3, column=0, columnspan=3, sticky="w", pady=(12, 0)
        )
        search_panel.columnconfigure(0, weight=3)
        search_panel.columnconfigure(1, weight=1)
        search_panel.columnconfigure(2, weight=1)

        workspace = ttk.Frame(tab, style="Panel.TFrame")
        workspace.pack(fill="both", expand=True, pady=(14, 0))
        self.search_workspace = workspace
        browser = ttk.Frame(workspace, padding=14, style="Panel.TFrame", relief="solid", borderwidth=1)
        inspector = ttk.Frame(workspace, padding=14, style="Panel.TFrame", relief="solid", borderwidth=1)
        self.search_browser = browser
        self.search_inspector = inspector
        browser.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        inspector.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        workspace.columnconfigure(0, weight=3)
        workspace.columnconfigure(1, weight=2)
        workspace.rowconfigure(0, weight=1)

        browser_top = ttk.Frame(browser, style="Panel.TFrame")
        browser_top.pack(fill="x", pady=(0, 9))
        self.search_result_var = tk.StringVar(value="Archivio catalogato")
        ttk.Label(browser_top, textvariable=self.search_result_var, style="Section.TLabel").pack(side="left")
        ttk.Label(browser_top, text="apri le cartelle con il triangolo", style="Utility.TLabel").pack(side="right")
        tree_frame = ttk.Frame(browser, style="Panel.TFrame")
        tree_frame.pack(fill="both", expand=True)
        self.search_tree = ttk.Treeview(
            tree_frame,
            columns=("size", "cassette", "copied"),
            show="tree headings",
            selectmode="browse",
        )
        self.search_tree.heading("#0", text="Libreria / cartella / file")
        self.search_tree.heading("size", text="Dimensione")
        self.search_tree.heading("cassette", text="Cassetta")
        self.search_tree.heading("copied", text="Copiato")
        self.search_tree.column("#0", width=390, minwidth=220, stretch=True)
        self.search_tree.column("size", width=105, minwidth=80, stretch=False)
        self.search_tree.column("cassette", width=105, minwidth=85, stretch=False)
        self.search_tree.column("copied", width=145, minwidth=110, stretch=False)
        tree_y = ttk.Scrollbar(tree_frame, orient="vertical", command=self.search_tree.yview)
        tree_x = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.search_tree.xview)
        self.search_tree.configure(yscrollcommand=tree_y.set, xscrollcommand=tree_x.set)
        self.search_tree.grid(row=0, column=0, sticky="nsew")
        tree_y.grid(row=0, column=1, sticky="ns")
        tree_x.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.search_tree.bind("<<TreeviewOpen>>", self._explorer_open)
        self.search_tree.bind("<<TreeviewSelect>>", self._explorer_selected)

        ttk.Label(inspector, text="Scheda del file", style="Section.TLabel").pack(anchor="w")
        self.explorer_detail_title = tk.StringVar(value="Seleziona un file nell'albero o nei risultati.")
        ttk.Label(
            inspector, textvariable=self.explorer_detail_title, style="Panel.TLabel", wraplength=430,
        ).pack(anchor="w", fill="x", pady=(7, 10))
        self.explorer_details = tk.Text(
            inspector,
            relief="flat",
            borderwidth=0,
            bg="#f5f8f9",
            fg=self.TEXT,
            font=("Cascadia Mono", 9),
            padx=12,
            pady=11,
            wrap="word",
            state="disabled",
        )
        details_y = ttk.Scrollbar(inspector, orient="vertical", command=self.explorer_details.yview)
        self.explorer_details.configure(yscrollcommand=details_y.set)
        details_y.pack(side="right", fill="y")
        self.explorer_details.pack(side="left", fill="both", expand=True)
        self._search_rows: dict[str, dict] = {}
        self._explorer_nodes: dict[str, dict] = {}
        self._explorer_library_signature: tuple = ()
        self._explorer_mode = "tree"

    def _build_catalog_tab(self) -> None:
        tab = self._new_tab("Catalogo")
        toolbar = ttk.Frame(tab, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, 10))
        self.catalog_toolbar = toolbar
        self.catalog_toolbar_title = ttk.Label(
            toolbar, text="Nastri e blocchi", style="Section.TLabel"
        )
        self.catalog_toolbar_title.pack(side="left")
        self._button(toolbar, "Esporta catalogo", self._export_catalog).pack(side="right")
        self._button(toolbar, "Controlla integrità", self._catalog_check).pack(side="right", padx=8)
        self._button(toolbar, "Dimentica blocco", self._forget_block, "Danger.TButton").pack(side="right")
        self.catalog_toolbar_buttons = [
            child for child in toolbar.winfo_children() if isinstance(child, ttk.Button)
        ]

        panes = ttk.Panedwindow(tab, orient="vertical")
        panes.pack(fill="both", expand=True)
        tape_panel = ttk.Frame(panes, padding=10, style="Panel.TFrame")
        block_panel = ttk.Frame(panes, padding=10, style="Panel.TFrame")
        panes.add(tape_panel, weight=1)
        panes.add(block_panel, weight=2)
        ttk.Label(tape_panel, text="Nastri", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
        self.tapes_tree = self._tree(
            tape_panel,
            ("id", "cassette", "label", "serial", "filesystem", "mount", "status"),
            ("ID", "N. cassetta", "Etichetta", "Seriale", "FS", "Ultimo mount", "Stato"),
            (115, 110, 145, 115, 60, 120, 80),
        )
        self.tapes_tree.pack(fill="both", expand=True)
        ttk.Label(block_panel, text="Blocchi", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
        self.blocks_tree = self._tree(
            block_panel,
            ("id", "library", "tape", "status", "visible", "files", "size", "started"),
            ("ID blocco", "Libreria", "Nastro", "Stato", "Catalogo", "File", "Dimensione", "Avviato"),
            (180, 100, 100, 90, 90, 70, 110, 165),
        )
        self.blocks_tree.pack(fill="both", expand=True)

    def _build_statusbar(self) -> None:
        frame = ttk.Frame(self.main, padding=(28, 8, 28, 12), style="Workspace.TFrame")
        frame.pack(side="bottom", fill="x")
        self.status_frame = frame
        self.status_var = tk.StringVar(value="Avvio...")
        self.status_path_label = ttk.Label(
            frame, text=str(self.application.paths.state_dir), style="Subtitle.TLabel"
        )
        self.status_path_label.pack(side="right")
        self.footer_progress = ttk.Progressbar(frame, maximum=100, mode="determinate", length=180)
        self.footer_progress.pack(side="right", padx=(14, 20))
        self.status_message_field = stable_status_field(
            frame,
            self.status_var,
            height=22,
            background=self.BG,
            foreground=self.MUTED,
            font=("Segoe UI Variable Text", 9),
        )
        self.status_message_field.pack(side="left", fill="x", expand=True)
        self.status_message_label = self.status_message_field.winfo_children()[0]

    def _button(self, parent: tk.Misc, text: str, command: Callable, style: str = "TButton") -> ttk.Button:
        button = ttk.Button(parent, text=text, command=command, style=style)
        self._action_buttons.append(button)
        return button

    @staticmethod
    def _tree(parent: tk.Misc, columns: tuple[str, ...], headings: tuple[str, ...], widths: tuple[int, ...]) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
        vertical = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        vertical.pack(side="right", fill="y")
        horizontal.pack(side="bottom", fill="x")
        for column, heading, width in zip(columns, headings, widths):
            tree.heading(column, text=heading)
            tree.column(column, width=width, minwidth=50, stretch=column in ("source", "id", "path"))
        return tree

    @staticmethod
    def _labeled_entry(parent: ttk.Frame, row: int, column: int, label: str, variable: tk.StringVar, width: int = 30) -> None:
        ttk.Label(parent, text=label, style="Panel.TLabel").grid(row=row, column=column, sticky="w", padx=(0, 10), pady=(0, 4))
        ttk.Entry(parent, textvariable=variable, width=width).grid(row=row + 1, column=column, sticky="ew", padx=(0, 10))

    @staticmethod
    def _labeled_combo(parent: ttk.Frame, row: int, column: int, label: str, variable: tk.StringVar) -> None:
        ttk.Label(parent, text=label, style="Panel.TLabel").grid(row=row, column=column, sticky="w", padx=(0, 10), pady=(0, 4))
        ttk.Combobox(parent, textvariable=variable, state="readonly").grid(row=row + 1, column=column, sticky="ew", padx=(0, 10))

    def refresh(self) -> None:
        self._run_task("Aggiornamento catalogo", self.application.snapshot, self._apply_snapshot, show_success=False)

    def _apply_snapshot(self, snapshot: dict) -> None:
        self._snapshot = snapshot
        self.verify_unchanged_content.set(
            bool(snapshot["settings"].get("verify_unchanged_content", False))
        )
        libraries = snapshot["libraries"]
        tapes = snapshot["tapes"]
        blocks = snapshot["blocks"]
        automatic_jobs = snapshot.get("automatic_jobs", [])
        job_word = "job salvato" if len(automatic_jobs) == 1 else "job salvati"
        self.automatic_jobs_catalog_summary.set(
            f"{len(automatic_jobs)} {job_word} | seleziona il job da gestire"
        )
        active_libraries = [row for row in libraries if row["status"] == "active"]
        completed = [row for row in blocks if row["status"] == "completed" and row["visible"]]
        self.card_vars["libraries"].set(str(len(active_libraries)))
        self.card_vars["tapes"].set(str(len(tapes)))
        self.card_vars["blocks"].set(str(len(completed)))
        self.card_vars["reserve"].set(human_bytes(snapshot["settings"]["reserve_bytes"]))

        self._replace_tree(
            self.libraries_tree,
            (
                (
                    r["id"],
                    r["name"],
                    r["source_root"],
                    human_bytes(r["last_scan_bytes"])
                    if r.get("last_scan_bytes") is not None else "Non calcolata",
                    r["last_scan_files"] if r.get("last_scan_files") is not None else "-",
                    r.get("last_scanned_at") or "-",
                    self._status(r["status"]),
                    r["created_at"],
                )
                for r in libraries
            ),
            (r["id"] for r in libraries),
        )
        self._replace_tree(
            self.tapes_tree,
            (
                (
                    r["id"],
                    r["cassette_number"],
                    r["volume_label"],
                    r["volume_serial"],
                    r["filesystem"],
                    r["mount_hint"],
                    self._status(r["status"]),
                )
                for r in tapes
            ),
            (r["id"] for r in tapes),
        )
        block_rows = [
            (
                r["id"], r["library_id"], r["tape_id"], self._status(r["status"]),
                "Visibile" if r["visible"] else "Dimenticato", r["copied_files"],
                human_bytes(r["copied_bytes"]), r["started_at"],
            )
            for r in blocks
        ]
        self._replace_tree(self.blocks_tree, block_rows, (r["id"] for r in blocks))
        self._replace_tree(
            self.overview_blocks,
            ((r["library_id"], r["tape_id"], self._status(r["status"]), r["copied_files"], human_bytes(r["copied_bytes"]), r["started_at"]) for r in blocks[:12]),
        )
        selected_job = self._automatic_job_id
        if not selected_job:
            selection = self.automatic_jobs_tree.selection()
            selected_job = selection[0] if selection else ""
        automatic_cassettes = snapshot.get("automatic_cassettes", [])
        job_views = []
        for row in automatic_jobs:
            queue_rows = [item for item in automatic_cassettes if item["job_id"] == row["id"]]
            view = build_automatic_job_view(row, queue_rows)
            libraries_label = ", ".join(row.get("library_ids") or [row.get("library_id", "")])
            job_views.append((row, view, libraries_label))
        self._replace_tree(
            self.automatic_jobs_tree,
            (
                (
                    automatic_job_label(row), libraries_label, self._status(row["status"]),
                    f"{view['completed_cassettes']} / {view['total_cassettes']}  "
                    f"({view['progress_percent']:.0f}%)"
                    + (f"  +{view['reserved_cassettes']}R" if view["reserved_cassettes"] else ""),
                    view["next_label"], row["created_at"],
                )
                for row, view, libraries_label in job_views
            ),
            (row["id"] for row in automatic_jobs),
        )
        for row, _view, _libraries_label in job_views:
            tag = {
                "completed": "job_completed",
                "failed": "job_failed",
            }.get(row["status"], "job_active")
            self.automatic_jobs_tree.item(row["id"], tags=(tag,))
        known_job_ids = {row["id"] for row in automatic_jobs}
        if selected_job in known_job_ids:
            self.automatic_jobs_tree.selection_set(selected_job)
            self.automatic_jobs_tree.focus(selected_job)
            self._automatic_job_id = selected_job
        elif automatic_jobs:
            self._automatic_job_id = automatic_jobs[0]["id"]
            self.automatic_jobs_tree.selection_set(self._automatic_job_id)
            self.automatic_jobs_tree.focus(self._automatic_job_id)
        else:
            self._automatic_job_id = ""
        self._refresh_automatic_queue()

        library_ids = [r["id"] for r in active_libraries]
        tape_ids = [r["id"] for r in tapes if r["status"] == "active"]
        all_library_ids = [r["id"] for r in libraries]
        self.backup_library_combo.configure(values=library_ids)
        self._active_automatic_libraries = active_libraries
        active_keys = {value.casefold() for value in library_ids}
        previous_inventory_ids = list(self._inventory_library_ids)
        self._inventory_library_ids = [
            value for value in self._inventory_library_ids if value.casefold() in active_keys
        ]
        if self._inventory_library_ids != previous_inventory_ids:
            self._inventory_plan = None
            self.inventory_use_button.configure(state="disabled")
        self._update_inventory_libraries_summary()
        self._automatic_library_ids = [
            value for value in self._automatic_library_ids if value.casefold() in active_keys
        ]
        if not self._automatic_library_ids and library_ids:
            self._automatic_library_ids = list(library_ids)
        self._update_automatic_libraries_summary()
        self.backup_tape_combo.configure(values=tape_ids)
        self.restore_library_combo.configure(values=all_library_ids)
        self.restore_tape_combo.configure(values=tape_ids)
        self.search_library_combo.configure(values=["Tutte", *all_library_ids])
        self._select_default(self.backup_library, library_ids)
        self._select_default(self.backup_tape, tape_ids)
        self._select_default(self.restore_library, all_library_ids)
        self._select_default(self.restore_tape, tape_ids)
        if self.search_library.get() not in ["Tutte", *all_library_ids]:
            self.search_library.set("Tutte")
        new_signature = explorer_library_signature(libraries)
        if should_reset_backup_explorer(
            self._explorer_mode,
            self._explorer_library_signature,
            new_signature,
        ):
            self._reset_backup_explorer(libraries)
        self.header_state_dot.configure(fg=self.SUCCESS)
        self.header_state.configure(text=" Catalogo pronto", fg=self.TEXT)
        self.status_var.set("Catalogo aggiornato")

    @staticmethod
    def _replace_tree(tree: ttk.Treeview, rows, item_ids=None) -> None:
        tree.delete(*tree.get_children())
        tree.tag_configure("even", background="#f2f6f7")
        tree.tag_configure("odd", background="#fcfdfd")
        ids = list(item_ids) if item_ids is not None else []
        for index, values in enumerate(rows):
            item_id = ids[index] if index < len(ids) else ""
            tree.insert("", "end", iid=item_id or None, values=values, tags=("even" if index % 2 == 0 else "odd",))

    @staticmethod
    def _select_default(variable: tk.StringVar, values: list[str]) -> None:
        if variable.get() not in values:
            variable.set(values[0] if values else "")

    @staticmethod
    def _status(value: str) -> str:
        return {
            "active": "Attivo",
            "retired": "Ritirato",
            "copying": "In copia",
            "completed": "Completato",
            "failed": "Fallito",
            "planned": "Pianificato",
            "waiting_media": "Attesa cassetta",
            "formatting": "Formattazione",
            "mounting": "Mount LTFS",
            "writing": "Scrittura",
            "unmounting": "Espulsione",
            "paused": "In pausa",
            "pending": "Da fare",
        }.get(value, value)

    def _selected_id(self, tree: ttk.Treeview, what: str) -> str | None:
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("Selezione richiesta", f"Selezionare {what}.", parent=self)
            return None
        return selected[0]

    def _add_library(self) -> None:
        dialog = LibraryDialog(self)
        self.wait_window(dialog)
        if dialog.result:
            library_id, name, source = dialog.result
            self._run_task(
                "Aggiunta libreria",
                lambda: self.application.add_library(library_id, name, source),
                lambda _result: self.refresh(),
            )

    def _delete_library(self) -> None:
        library_id = self._selected_id(self.libraries_tree, "una libreria")
        if not library_id:
            return
        if not messagebox.askyesno(
            "Eliminare la libreria dal catalogo?",
            f"Saranno cancellati dal catalogo tutti i file, i blocchi e i riferimenti "
            f"della libreria {library_id}.\n\n"
            "I file originali SMB e i dati scritti sui nastri non saranno modificati. "
            "Le altre librerie e il registro delle cassette resteranno intatti.",
            icon="warning",
            parent=self,
        ):
            return
        self._run_task(
            "Eliminazione libreria dal catalogo",
            lambda: self.application.delete_library(library_id),
            self._library_deleted,
        )

    def _library_deleted(self, result: dict) -> None:
        messagebox.showinfo(
            "Libreria eliminata",
            f"Libreria: {result['library_id']}\n"
            f"File rimossi dal catalogo: {result['catalog_files_deleted']}\n"
            f"Blocchi rimossi dal catalogo: {result['catalog_blocks_deleted']}\n\n"
            "Nessun file SMB o dato su nastro è stato cancellato.",
            parent=self,
        )
        self.refresh()

    def _scan_library(self) -> None:
        library_id = self._selected_id(self.libraries_tree, "una libreria")
        if not library_id:
            return
        self._run_task(
            "Scansione libreria",
            lambda: self.application.scan(library_id),
            self._scan_library_complete,
        )

    def _scan_library_complete(self, result: dict) -> None:
        self.scan_result_var.set(
            f"Dimensione libreria: {result['source_human']} / {result['source_files']} file - "
            f"da copiare: {result['files']} file / {result['human']} - "
            f"{result['skipped_unchanged']} invariati - "
            f"{result['skipped_too_recent']} troppo recenti"
        )
        self.refresh()

    def _toggle_content_verification(self) -> None:
        enabled = bool(self.verify_unchanged_content.get())
        self.application.configure_content_verification(enabled)
        self.scan_result_var.set(
            self._t("Verifica SHA-256 completa attiva: le scansioni possono richiedere molte ore.")
            if enabled else
            self._t("Verifica rapida attiva: i file invariati sono riconosciuti da dimensione e data.")
        )

    def _scan_all_libraries(self) -> None:
        active = [row for row in self._snapshot.get("libraries", []) if row["status"] == "active"]
        if not active:
            messagebox.showinfo("Scansione librerie", "Non ci sono librerie attive da scansionare.", parent=self)
            return
        self.progress_tracker.reset()
        self.progress_bar["value"] = 0
        self.footer_progress["value"] = 0
        self.library_scan_progress["value"] = 0
        self._run_task(
            "Scansione di tutte le librerie",
            lambda: self.application.scan_all_libraries(progress=self._enqueue_progress),
            self._scan_all_complete,
            show_success=False,
        )

    def _scan_all_complete(self, result: dict) -> None:
        self.progress_bar["value"] = 100
        self.footer_progress["value"] = 100
        self.library_scan_progress["value"] = 100
        summary = (
            f"Scansione completata: {result['completed_libraries']}/{result['total_libraries']} librerie - "
            f"dimensione totale {result['source_human']} / {result['source_files']} file - "
            f"da copiare {result['total_files']} file / {result['total_human']}"
        )
        self.scan_result_var.set(summary)
        self.operation_var.set(summary)
        self._append_log(summary)
        details = "\n".join(
            f"{row['library_id']}: totale {row['source_human']} / {row['source_files']} file; "
            f"da copiare {row['human']} / {row['files']} file"
            for row in result["libraries"]
        )
        messagebox.showinfo(
            "Scansione completata",
            summary + ("\n\n" + details if details else ""),
            parent=self,
        )
        self.refresh()

    def _media_selection_changed(self, target: str) -> None:
        variable = (
            self.inventory_media_key if target == "inventory" else self.automatic_media_key
        )
        profile = get_lto_media_profile(variable.get())
        ltfs = (
            _decimal_tb(profile.ltfs_usable_tb)
            if profile.ltfs_usable_tb is not None
            else "non disponibile: LTFS richiede LTO-5 o successiva"
        )
        description = (
            f"Nativa {_decimal_tb(profile.native_capacity_tb)}  |  "
            f"LTFS utilizzabile {ltfs}  |  compressa teorica "
            f"{_decimal_tb(profile.compressed_capacity_tb)}  |  barcode {profile.barcode_suffix}"
        )
        if target == "inventory":
            self.inventory_media_description.set(description)
            if hasattr(self, "inventory_reserve_note"):
                self.inventory_reserve_note.set(
                    description + ". Il piano usa la capacita LTFS, non quella compressa teorica."
                )
            if hasattr(self, "inventory_use_button"):
                self._inventory_plan = None
                self.inventory_use_button.configure(state="disabled")
                self.inventory_summary.set(
                    "Tipo cassetta modificato: calcola nuovamente il piano cumulativo."
                )
        else:
            self.automatic_labels_hint.set(
                f"Etichette {profile.key}, una per riga (ABC123 oppure "
                f"ABC123{profile.barcode_suffix}). Quelle eccedenti resteranno in riserva futura."
            )

    def _analyze_inventory(self) -> None:
        library_ids = list(self._inventory_library_ids)
        if not library_ids:
            messagebox.showwarning(
                "Piano del job", "Selezionare almeno una libreria da includere nel job.", parent=self
            )
            return
        self.inventory_use_button.configure(state="disabled")
        self.inventory_summary.set(
            f"Scansione di {len(library_ids)} librerie e calcolo della distribuzione cumulativa..."
        )
        self.progress_tracker.reset()
        self.progress_bar["value"] = 0
        self.footer_progress["value"] = 0
        self._run_task(
            "Calcolo piano del job",
            lambda: self.application.plan_automatic_job(
                library_ids,
                progress=self._enqueue_progress,
                media_key=self.inventory_media_key.get(),
            ),
            self._show_inventory,
            show_success=False,
        )

    def _show_inventory(self, result: dict) -> None:
        self._inventory_plan = result
        self.inventory_card_vars["libraries"].set(str(result["total_libraries"]))
        self.inventory_card_vars["pending"].set(result["pending_human"])
        self.inventory_card_vars["files"].set(str(result["pending_files"]))
        self.inventory_card_vars["tapes"].set(str(result["estimated_tapes"]))
        if result["estimated_tapes"]:
            self.inventory_summary.set(
                f"Piano pronto: {result['total_libraries']} librerie formano un solo job; "
                f"{result['pending_files']} file ({result['pending_human']}) sono distribuiti su "
                f"{result['estimated_tapes']} cassette. Controlla la sequenza, poi prepara il job."
            )
            self.inventory_use_button.configure(state="normal")
        else:
            self.inventory_summary.set(
                "Nessun dato nuovo da copiare nelle librerie selezionate. Il job non richiede cassette."
            )
            self.inventory_use_button.configure(state="disabled")
        self.inventory_reserve_note.set(
            f"Stima {result['media_key']}: capacita nativa "
            f"{_decimal_tb(result['native_tape_tb'])}; dati LTFS "
            f"{_decimal_tb(result['nominal_tape_tb'])} ({result['nominal_tape_human']} in unita binarie); "
            f"margine extra "
            f"{result['reserve_human']}; utilizzabili per piano {result['usable_tape_human']}. "
            "La capacita compressa e solo teorica; il lotto reale usa lo spazio libero "
            "comunicato dalla cassetta montata."
        )
        self._replace_tree(
            self.inventory_plan_tree,
            ((
                f"{row['sequence']} di {result['estimated_tapes']}",
                " + ".join(item["library_id"] for item in row["libraries"]),
                row["file_count"], row["human"],
                f"{row['utilization_percent']:.1f}%", row["remaining_human"],
            ) for row in result["cassettes"]),
        )
        self._replace_tree(
            self.inventory_distribution_tree,
            (
                (
                    f"Cassetta {cassette['sequence']}", item["library_id"],
                    item["file_count"], item["human"],
                    f"{item['total_bytes'] * 100 / cassette['total_bytes']:.1f}%"
                    if cassette["total_bytes"] else "0.0%",
                )
                for cassette in result["cassettes"]
                for item in cassette["libraries"]
            ),
        )
        self._replace_tree(
            self.inventory_libraries_tree,
            (
                (
                    row["library_id"], row["name"],
                    f"{row['total_files']} file / {row['total_human']}",
                    f"{row['pending_files']} file / {row['pending_human']}",
                    row["archived_files"], row["too_recent_files"],
                )
                for row in result["libraries"]
            ),
        )

    def _select_inventory_libraries(self) -> None:
        dialog = LibrarySelectionDialog(
            self,
            getattr(self, "_active_automatic_libraries", []),
            self._inventory_library_ids,
        )
        self.wait_window(dialog)
        if dialog.result is not None:
            self._inventory_library_ids = dialog.result
            self._inventory_plan = None
            self.inventory_use_button.configure(state="disabled")
            self._update_inventory_libraries_summary()
            for key, value in (("libraries", str(len(dialog.result))), ("pending", "-"), ("files", "-"), ("tapes", "-")):
                self.inventory_card_vars[key].set(value)
            self.inventory_summary.set(
                "Selezione modificata: calcola nuovamente il piano cumulativo del job."
            )
            self._replace_tree(self.inventory_plan_tree, ())
            self._replace_tree(self.inventory_distribution_tree, ())
            self._replace_tree(self.inventory_libraries_tree, ())

    def _update_inventory_libraries_summary(self) -> None:
        if not self._inventory_library_ids:
            self.inventory_libraries_summary.set("Nessuna libreria selezionata")
            return
        self.inventory_libraries_summary.set(
            f"{len(self._inventory_library_ids)} librerie nello stesso job: "
            + ", ".join(self._inventory_library_ids)
        )

    def _use_inventory_plan(self) -> None:
        if not self._inventory_plan or not self._inventory_plan["estimated_tapes"]:
            messagebox.showinfo(
                "Piano non disponibile", "Calcolare prima un piano che richieda almeno una cassetta.", parent=self
            )
            return
        self._automatic_library_ids = list(self._inventory_plan["library_ids"])
        self.automatic_media_key.set(self._inventory_plan["media_key"])
        self._media_selection_changed("automatic")
        self._update_automatic_libraries_summary()
        self.automatic_plan_hint.set(
            f"Piano importato: {self._inventory_plan['total_libraries']} librerie, "
            f"{self._inventory_plan['pending_files']} file / {self._inventory_plan['pending_human']}, "
            f"servono almeno {self._inventory_plan['estimated_tapes']} etichette; "
            "quelle aggiuntive resteranno in riserva futura."
        )
        self._show_page("automatic")
        self.automatic_labels.focus_set()

    def _select_automatic_libraries(self) -> None:
        dialog = LibrarySelectionDialog(
            self,
            getattr(self, "_active_automatic_libraries", []),
            self._automatic_library_ids,
        )
        self.wait_window(dialog)
        if dialog.result is not None:
            self._automatic_library_ids = dialog.result
            self._update_automatic_libraries_summary()
            self.automatic_plan_hint.set(
                "Selezione manuale: crea il piano da Piano cassette per conoscere prima "
                "numero e distribuzione delle cassette."
            )

    def _update_automatic_libraries_summary(self) -> None:
        count = len(self._automatic_library_ids)
        if not count:
            self.automatic_libraries_summary.set("Nessuna libreria selezionata")
            return
        labels = ", ".join(self._automatic_library_ids)
        self.automatic_libraries_summary.set(f"{count} librerie: {labels}")

    def _create_automatic_job(self) -> None:
        libraries = list(self._automatic_library_ids)
        device = self.automatic_device.get().strip()
        mount = self.automatic_mount.get().strip()
        labels = self.automatic_labels.get("1.0", "end").splitlines()
        labels = [label.strip() for label in labels if label.strip()]
        if not libraries or not device or not labels:
            messagebox.showwarning(
                "Dati mancanti", "Selezionare le librerie, il drive e indicare le etichette.", parent=self
            )
            return
        if not self.automatic_confirm.get():
            messagebox.showwarning(
                "Conferma richiesta", "Spuntare la conferma di formattazione automatica.", parent=self
            )
            return
        try:
            creation_context = self.application.automatic_job_creation_context(
                libraries, device
            )
        except LtoBackupError as exc:
            messagebox.showerror("Impossibile verificare i job salvati", str(exc), parent=self)
            return
        conflicts = creation_context["conflicting_jobs"]
        if conflicts:
            details = "\n".join(
                f"- {automatic_job_label(row)} ({row['id']}): "
                f"{', '.join(row['overlapping_libraries'])}"
                for row in conflicts
            )
            messagebox.showinfo(
                "Librerie gia impegnate",
                "Le librerie indicate appartengono gia a un job non concluso:\n\n"
                f"{details}\n\nSelezionare quel job e usare Avvia / riprendi, oppure "
                "completarlo o eliminarlo prima di creare un nuovo piano.",
                parent=self,
            )
            return
        reuse_registered = self.automatic_reuse_registered.get()
        reuse_warning = (
            "\n\nCASSETTE GIA REGISTRATE: hai autorizzato la riformattazione. "
            "Dopo una formattazione riuscita, i vecchi file e blocchi di quel supporto "
            "saranno rimossi definitivamente dal catalogo."
            if reuse_registered else ""
        )
        other_jobs = creation_context["saved_on_device"]
        saved_jobs_note = (
            "\n\nALTRI JOB SALVATI SUL DRIVE: "
            + ", ".join(f"{automatic_job_label(row)} ({row['id']})" for row in other_jobs)
            + ". Non esiste un ordine FIFO automatico: resteranno salvati e non partiranno."
            if other_jobs else ""
        )
        if not messagebox.askyesno(
            "Salvare il job automatico?",
            f"Librerie cumulative ({len(libraries)}): {', '.join(libraries)}\n"
            f"Drive: {device}\nLettera LTFS: automatica\nCassette: {len(labels)}\n\n"
            f"Tipo supporto: {self.automatic_media_key.get()}\n"
            "Ordine richiesto:\n" + "\n".join(f"  {index}. {label}" for index, label in enumerate(labels, 1))
            + "\n\nIl job verra soltanto salvato. Per usare il drive dovrai selezionarlo "
              "e premere Avvia / riprendi job selezionato."
            + saved_jobs_note
            + "\n\nATTENZIONE: ogni supporto inserito, anche se gia LTFS, sara riformattato "
              "e perdera tutti i dati. Il drive non puo verificare "
              "l'etichetta adesiva: l'operatore deve inserire quella richiesta."
            + reuse_warning,
            icon="warning",
            parent=self,
        ):
            return
        self._run_task(
            "Creazione job automatico",
            lambda: self.application.create_automatic_job(
                libraries,
                labels,
                device_name=device,
                mount=Path(mount),
                destructive_confirmed=True,
                media_key=self.automatic_media_key.get(),
                allow_registered_reuse=reuse_registered,
            ),
            self._automatic_created,
            show_success=False,
        )

    def _automatic_created(self, job: dict) -> None:
        self._automatic_job_id = job["id"]
        self.automatic_confirm.set(False)
        self.automatic_reuse_registered.set(False)
        self.automatic_labels.delete("1.0", "end")
        self.automatic_state.set(
            "Job salvato nel catalogo: non e ancora in esecuzione. "
            "Selezionalo e premi Avvia / riprendi job selezionato."
        )
        self.refresh()
        messagebox.showinfo(
            "Job salvato",
            f"Il job {job['id']} e stato salvato ma non e stato avviato.\n\n"
            "Per iniziare, selezionalo nell'elenco e premi "
            "Avvia / riprendi job selezionato.",
            parent=self,
        )

    def _continue_automatic_job(self) -> None:
        job_id = self._selected_id(self.automatic_jobs_tree, "un job automatico")
        if not job_id:
            return
        job = next(
            (row for row in self._snapshot.get("automatic_jobs", []) if row["id"] == job_id),
            None,
        )
        if not job:
            return
        cassettes = [
            row for row in self._snapshot.get("automatic_cassettes", [])
            if row["job_id"] == job_id
        ]
        labels = [
            label.strip()
            for label in self.automatic_labels.get("1.0", "end").splitlines()
            if label.strip()
        ]
        try:
            action = choose_existing_job_action(job, cassettes, labels)
        except ValidationError as exc:
            messagebox.showinfo("Come continuare il job", str(exc), parent=self)
            return
        if action == "resume":
            try:
                start_context = self.application.automatic_job_start_context(job_id)
            except LtoBackupError as exc:
                messagebox.showerror("Impossibile verificare l'avvio", str(exc), parent=self)
                return
            next_cassette = start_context.get("next_cassette")
            next_label = (
                str(next_cassette.get("physical_label") or "-")
                if next_cassette else "da pianificare"
            )
            other_jobs = start_context["other_jobs_on_device"]
            other_jobs_note = (
                "\n\nAltri job non conclusi sullo stesso drive:\n"
                + "\n".join(
                    f"- {automatic_job_label(row)} ({row['id']}), stato {row['status']}"
                    for row in other_jobs
                )
                + "\nResteranno salvati: non verranno avviati automaticamente dopo questo job."
                if other_jobs else ""
            )
            if not messagebox.askyesno(
                "Avviare il job selezionato?",
                f"Job: {automatic_job_label(start_context['job'])} ({job_id})\n"
                f"Drive: {start_context['job']['device_name']}\n"
                f"Prossima cassetta: {next_label}\n\n"
                "Partira esclusivamente questo job. Una cassetta NUOVA verra riformattata "
                "come previsto dal piano; una cassetta APPEND conservera i dati esistenti."
                + other_jobs_note,
                icon="warning",
                parent=self,
            ):
                return
            self._run_automatic_job(job_id)
            return
        if not self.automatic_confirm.get():
            messagebox.showwarning(
                "Conferma richiesta",
                "Spuntare la conferma di formattazione automatica.",
                parent=self,
            )
            return
        reuse_registered = self.automatic_reuse_registered.get()
        first_sequence = int(job["total_cassettes"]) + 1
        if str(job.get("status") or "") in {"planned", "paused", "waiting_media"}:
            extension_detail = (
                "Le nuove etichette verranno accodate senza spostare i file gia assegnati. "
                "I file nuovi useranno prima lo spazio residuo delle cassette future, poi "
                "le riserve e infine questi nuovi supporti."
            )
        else:
            extension_detail = (
                "Se l'ultima cassetta completata ha ancora spazio, verra prima riaperta in "
                "APPEND senza formattazione e senza cancellare i blocchi esistenti."
            )
        if not messagebox.askyesno(
            "Aggiungere cassette al job?",
            f"Job: {job_id}\nLibrerie: {', '.join(job.get('library_ids', []))}\n\n"
            "Nuova sequenza richiesta:\n"
            + "\n".join(
                f"  {first_sequence + offset}. {label}"
                for offset, label in enumerate(labels)
            )
            + "\n\nSaranno pianificati soltanto i file nuovi. Ogni supporto inserito, "
              "anche se gia LTFS, sara riformattato e perdera tutti i dati. "
            + extension_detail
            + (
                "\n\nCASSETTE GIA REGISTRATE: hai autorizzato la riformattazione. "
                "Dopo una formattazione riuscita, i vecchi file e blocchi di quel supporto "
                "saranno rimossi definitivamente dal catalogo."
                if reuse_registered else ""
            )
            + "\n\nDopo l'accodamento, il job selezionato verra avviato dal checkpoint. "
              "Gli altri job salvati non verranno avviati automaticamente.",
            icon="warning",
            parent=self,
        ):
            return
        self._run_task(
            "Estensione job automatico",
            lambda: self.application.extend_automatic_job(
                job_id,
                labels,
                destructive_confirmed=True,
                allow_registered_reuse=reuse_registered,
            ),
            self._automatic_extended,
            show_success=False,
        )

    def _automatic_extended(self, job: dict) -> None:
        self._automatic_job_id = job["id"]
        self.automatic_confirm.set(False)
        self.automatic_reuse_registered.set(False)
        self.automatic_labels.delete("1.0", "end")
        self.automatic_state.set(
            "Nuove cassette accodate al job selezionato; avvio esplicito dal checkpoint sicuro..."
        )
        self.refresh()
        self.after(250, lambda: self._run_automatic_job(job["id"]))

    def _rename_automatic_job(self) -> None:
        job_id = self._selected_id(self.automatic_jobs_tree, "un job automatico")
        job = next(
            (row for row in self._snapshot.get("automatic_jobs", []) if row["id"] == job_id),
            None,
        )
        if job is None:
            raise ValidationError(f"Job automatico non trovato: {job_id}")
        name = simpledialog.askstring(
            self._t("Rinomina job"),
            self._t("Nuovo nome del job:"),
            initialvalue=automatic_job_label(job),
            parent=self,
        )
        if name is None:
            return
        self._run_task(
            self._t("Rinomina job"),
            lambda: self.application.rename_automatic_job(job_id, name),
            self._automatic_job_renamed,
        )

    def _automatic_job_renamed(self, job: dict) -> None:
        self._automatic_job_id = job["id"]
        self.refresh()

    def _delete_automatic_job(self) -> None:
        job_id = self._selected_id(self.automatic_jobs_tree, "un job automatico")
        if not job_id:
            return
        job = next(
            (row for row in self._snapshot.get("automatic_jobs", []) if row["id"] == job_id),
            None,
        )
        if job is None:
            messagebox.showinfo(
                self._t("Elimina job"),
                self._t("Il job selezionato non esiste piu nel catalogo."),
                parent=self,
            )
            return
        if not messagebox.askyesno(
            self._t("Eliminare il job selezionato?"),
            f"{self._t('Nome job')}: {automatic_job_label(job)}\n"
            f"ID: {job_id}\n\n"
            + self._t(
                "Verranno eliminate soltanto la definizione del job e la sua coda cassette. "
                "Librerie, file catalogati, blocchi completati, cassette registrate e dati LTFS "
                "non saranno modificati. L'operazione non puo essere annullata."
            ),
            icon="warning",
            parent=self,
        ):
            return
        self._run_task(
            self._t("Elimina job"),
            lambda: self.application.delete_automatic_job(job_id),
            self._automatic_job_deleted,
            show_success=False,
        )

    def _automatic_job_deleted(self, result: dict) -> None:
        self._automatic_job_id = ""
        self.automatic_state.set(
            self._t("Job eliminato dal catalogo; librerie, nastri e backup sono invariati.")
        )
        self.refresh()
        messagebox.showinfo(
            self._t("Job eliminato"),
            f"{result.get('display_name') or result['id']}\n\n"
            + self._t(
                "Definizione e coda eliminate. Nessun file, blocco completato, nastro o dato LTFS "
                "e stato cancellato."
            ),
            parent=self,
        )

    def _retry_failed_automatic_cassette(self) -> None:
        job_id = self._selected_id(self.automatic_jobs_tree, "un job automatico")
        if not job_id:
            return
        job = next(
            (row for row in self._snapshot.get("automatic_jobs", []) if row["id"] == job_id),
            None,
        )
        cassettes = [
            row for row in self._snapshot.get("automatic_cassettes", [])
            if row["job_id"] == job_id
        ]
        failed = failed_cassette_to_retry(job or {}, cassettes)
        if failed is None:
            messagebox.showinfo(
                "Cassetta in errore",
                "Il job selezionato non contiene una cassetta in errore da riprovare.",
                parent=self,
            )
            return
        sequence = int(failed["sequence"])
        label = str(failed.get("physical_label") or "-")
        is_append = failed.get("operation") == "append"
        retry_detail = (
            "Il nuovo tentativo APPEND verra scartato logicamente; i blocchi precedenti e il "
            "nastro catalogato resteranno invariati. Il job rimonta la stessa cassetta senza "
            "formattarla e riprova soltanto i file nuovi."
            if is_append else
            "Il tentativo incompleto verra rimosso dal catalogo. Le cassette gia completate "
            "non saranno modificate. Il job ripartira subito, attendera questa cassetta senza "
            "timeout e la riformattera LTFS da zero."
        )
        if not messagebox.askyesno(
            "Reimpostare e riprovare la cassetta?",
            f"Job: {automatic_job_label(job or {})}\n"
            f"Cassetta {sequence}: {label}\n\n"
            + retry_detail,
            icon="warning",
            parent=self,
        ):
            return
        self._run_task(
            "Reimpostazione cassetta in errore",
            lambda: self.application.reset_failed_automatic_cassette(job_id, sequence),
            self._automatic_cassette_reset,
            show_success=False,
        )

    def _automatic_cassette_reset(self, job: dict) -> None:
        self._automatic_job_id = job["id"]
        sequence = int(job.get("current_sequence") or 0)
        self.automatic_state.set(
            f"Cassetta {sequence} reimpostata; riavvio del job dal checkpoint sicuro..."
        )
        self.refresh()
        self.after(350, lambda: self._run_automatic_job(job["id"]))

    def _run_automatic_job(self, job_id: str) -> None:
        if self._busy:
            self.after(250, lambda: self._run_automatic_job(job_id))
            return
        self._automatic_job_id = job_id
        self._automatic_stop_event.clear()
        self._automatic_writing = False
        self._automatic_last_write_at = None
        self._automatic_average_write_bps = 0.0
        self._automatic_live_write_bps = None
        self._automatic_timing_event = None
        self._automatic_timing_updated_at = None
        self._automatic_activity_event = None
        self._automatic_activity_started_at = None
        self._automatic_finalization_event = None
        self._automatic_finalization_updated_at = None
        self._automatic_telemetry_text = ""
        self.automatic_stop_button.configure(state="normal")
        self.automatic_state.set("Avvio del job automatico...")
        self.automatic_write_speed.set(
            write_speed_text(None, 0.0, language=self.language)
        )
        self.automatic_speed_chart.reset()
        self.automatic_finalize_phase.set(self._t("Inattivo"))
        self.automatic_finalize_detail.set(
            self._t("Nessuna finalizzazione in corso")
        )
        self.automatic_finalize_counter.set("-")
        self.automatic_finalize_elapsed.set("-")
        self.automatic_finalize_eta.set("-")
        self.automatic_finalize_progress["value"] = 0
        self._set_automatic_finalization_active(False)
        self._render_automatic_timing({})
        self.automatic_ltfs_activity.set(self._t("Telemetria LTFS: in attesa"))
        self.progress_tracker.reset()
        self._run_task(
            "Job automatico",
            lambda: self.application.run_automatic_job(
                job_id,
                progress=self._enqueue_progress,
                stop_requested=self._automatic_stop_event.is_set,
            ),
            self._automatic_finished,
            show_success=False,
        )

    def _automatic_finished(self, job: dict) -> None:
        self.automatic_stop_button.configure(state="disabled")
        self._automatic_writing = False
        self._automatic_activity_event = None
        self._automatic_activity_started_at = None
        self.automatic_ltfs_activity.set(self._t("Telemetria LTFS: ferma"))
        self._automatic_job_id = job["id"]
        if job["status"] == "completed":
            reserved = sum(
                row["status"] == "pending"
                and int(row.get("planned_files") or 0) == 0
                and int(row.get("planned_bytes") or 0) == 0
                for row in job.get("cassettes", [])
            )
            if reserved:
                message = (
                    f"Job completato; {reserved} "
                    f"{'cassetta resta' if reserved == 1 else 'cassette restano'} "
                    "in riserva futura e non sono state formattate."
                )
            else:
                message = "Job completato: tutte le cassette operative sono state scritte ed espulse."
            self.automatic_state.set(message)
            messagebox.showinfo("Job automatico", message, parent=self)
        elif job["status"] == "failed":
            self.automatic_state.set(f"Job non completato: {job.get('last_error') or 'controllare il dettaglio.'}")
            messagebox.showerror("Job automatico", self.automatic_state.get(), parent=self)
        else:
            self.automatic_state.set(
                "Job in pausa; il ciclo corrente verra ripreso in sicurezza alla prossima esecuzione."
            )
        self.automatic_write_speed.set(
            write_speed_text(
                None, self._automatic_average_write_bps, language=self.language
            )
        )
        self.refresh()

    def _stop_automatic_job(self) -> None:
        self._automatic_stop_event.set()
        self.automatic_stop_button.configure(state="disabled")
        self.automatic_state.set(
            "Interruzione richiesta: arresto al prossimo buffer, chiusura LTFS ed espulsione. "
            "I blocchi gia completati su una cassetta APPEND restano protetti."
        )

    def _automatic_job_selected(self, _event=None) -> None:
        selection = self.automatic_jobs_tree.selection()
        if selection:
            self._automatic_job_id = selection[0]
            self._refresh_automatic_queue()

    def _refresh_automatic_queue(self) -> None:
        job = next(
            (
                row for row in self._snapshot.get("automatic_jobs", [])
                if row["id"] == self._automatic_job_id
            ),
            None,
        )
        rows = [
            row for row in self._snapshot.get("automatic_cassettes", [])
            if row["job_id"] == self._automatic_job_id
        ]
        if job is None:
            self.automatic_retry_button.configure(state="disabled")
            self.automatic_selected_job_title.set("NESSUN JOB SELEZIONATO")
            self.automatic_selected_job_detail.set(
                "Nessun job salvato. Il primo job creato restera disponibile dopo la chiusura."
            )
            self.automatic_selected_job_checkpoint.set("CATALOGO PRONTO")
            self.automatic_selected_job_action.set("In attesa di una pianificazione")
            self.automatic_plan_hint.set(
                "Prima calcola il Piano cassette, oppure seleziona qui le librerie del job."
            )
            for variable in self.automatic_summary_vars.values():
                variable.set("-")
            self.automatic_job_progress["value"] = 0
            self._replace_tree(self.automatic_queue_tree, ())
            return

        view = build_automatic_job_view(job, rows)
        self.automatic_retry_button.configure(
            state="normal" if view["retry_sequence"] is not None else "disabled"
        )
        self.automatic_media_key.set(job.get("media_key", "LTO-6"))
        self._media_selection_changed("automatic")
        if job["status"] == "completed" and view["reserved_cassettes"]:
            self.automatic_plan_hint.set(
                f"Job {job['id']} selezionato: {view['reserved_cassettes']} riserve disponibili. "
                "Lascia vuote le etichette e premi Avvia / riprendi job selezionato."
            )
        elif job["status"] == "completed":
            self.automatic_plan_hint.set(
                f"Job {job['id']} concluso: usa Avvia / riprendi job selezionato per "
                "scrivere in APPEND nello spazio libero dell'ultima cassetta; aggiungi "
                "etichette se vuoi predisporre nuovi supporti."
            )
        else:
            self.automatic_plan_hint.set(
                f"Job {job['id']} selezionato: lascia vuote le etichette e premi "
                "Avvia / riprendi job selezionato."
            )
        library_ids = job.get("library_ids") or [job.get("library_id", "")]
        self.automatic_selected_job_title.set(
            f"JOB SELEZIONATO  |  {automatic_job_label(job)}"
        )
        self.automatic_selected_job_detail.set(
            f"ID: {job['id']}   |   Supporto: {job.get('media_key', 'LTO-6')}   |   "
            f"Librerie: {', '.join(library_ids)}   |   "
            f"Creato: {job.get('created_at') or '-'}"
        )
        self.automatic_selected_job_checkpoint.set(view["checkpoint"])
        self.automatic_selected_job_action.set(view["callout"])
        self.automatic_summary_vars["status"].set(self._status(job["status"]))
        self.automatic_summary_vars["cassettes"].set(
            f"{view['completed_cassettes']} / {view['total_cassettes']}"
            + (f"  +{view['reserved_cassettes']}R" if view["reserved_cassettes"] else "")
        )
        self.automatic_summary_vars["planned"].set(human_bytes(view["planned_bytes"]))
        self.automatic_summary_vars["copied"].set(human_bytes(view["copied_bytes"]))
        self.automatic_job_progress["value"] = view["progress_percent"]

        def operational_status(row: dict) -> str:
            if row["tag"] == "queue_reserved":
                return "Riserva futura - non richiesta"
            if row["tag"] == "queue_done":
                return "Completata ed espulsa"
            if row["tag"] == "queue_failed":
                return "Errore"
            if row["tag"] == "queue_current":
                return {
                    "planned": "Prima da inserire",
                    "waiting_media": "Da inserire adesso",
                    "paused": "Prossima alla ripresa",
                }.get(job["status"], self._status(job["status"]))
            return "In attesa"

        self._replace_tree(
            self.automatic_queue_tree,
            (
                (
                    f"{row['marker']}  {row['sequence']} / {view['queue_cassettes']}",
                    row["physical_label"], self._t(row["operation_label"]), operational_status(row),
                    f"{int(row.get('copied_files') or 0)} / {int(row.get('planned_files') or 0)}",
                    human_bytes(int(row.get("planned_bytes") or 0)),
                    human_bytes(int(row.get("copied_bytes") or 0)),
                    row.get("block_id") or "-",
                )
                for row in view["cassettes"]
            ),
        )
        for item_id, row in zip(
            self.automatic_queue_tree.get_children(), view["cassettes"]
        ):
            self.automatic_queue_tree.item(item_id, tags=(row["tag"],))

    def _register_tape(self) -> None:
        current_tape = self.backup_tape.get().strip()
        existing = next(
            (row for row in self._snapshot.get("tapes", []) if row["id"] == current_tape),
            None,
        )
        dialog = TapeDialog(
            self,
            initial_tape_id=current_tape,
            initial_cassette_number=existing["cassette_number"] if existing else "",
            initial_mount=self.backup_mount.get().strip(),
        )
        self.wait_window(dialog)
        if not dialog.result:
            return
        tape_id, cassette_number, mount = dialog.result
        self._run_task(
            "Registrazione nastro",
            lambda: self.application.register_tape(tape_id, cassette_number, Path(mount)),
            lambda result: self._registered_tape(result),
        )

    def _registered_tape(self, result: dict) -> None:
        messagebox.showinfo(
            "Nastro registrato",
            f"ID: {result['tape_id']}\nNumero cassetta: {result['cassette_number']}\n"
            f"Etichetta: {result['label']}\nSeriale: {result['serial']}\nLiberi: {result['free_human']}",
            parent=self,
        )
        self.backup_tape.set(result["tape_id"])
        self.refresh()

    def _search_files(self) -> None:
        query = self.search_query.get().strip()
        if not query:
            messagebox.showwarning(
                "Ricerca file",
                "Inserire il nome del file o una parte del percorso.",
                parent=self,
            )
            return
        selected_library = self.search_library.get().strip()
        library_id = None if selected_library in ("", "Tutte") else selected_library
        include_history = self.search_history.get()
        self._run_task(
            "Ricerca nel catalogo",
            lambda: self.application.search_files(
                query,
                library_id=library_id,
                include_history=include_history,
            ),
            self._show_search_results,
            show_success=False,
        )

    def _show_search_results(self, rows: list[dict]) -> None:
        self._explorer_mode = "search"
        self.search_tree.delete(*self.search_tree.get_children())
        self._search_rows = {}
        self._explorer_nodes = {}
        grouped: dict[str, list[dict]] = {}
        for row in rows:
            grouped.setdefault(row["library_id"], []).append(row)
        for library_id, library_rows in grouped.items():
            library_name = library_rows[0]["library_name"]
            root_id = f"results-library::{library_id}"
            self.search_tree.insert(
                "", "end", iid=root_id, text=f"{library_name}  [{library_id}]",
                values=(f"{len(library_rows)} risultati", "", ""), open=True,
            )
            self._explorer_nodes[root_id] = {
                "kind": "result_group", "library_id": library_id, "name": library_name,
            }
            for row in library_rows:
                item_id = f"result-file::{row['id']}"
                state = "Corrente" if row["is_current"] else "Storica"
                if not row["visible"]:
                    state += " / nascosta"
                display = dict(row)
                display["kind"] = "file"
                display["state_label"] = state
                self._search_rows[item_id] = display
                self._explorer_nodes[item_id] = display
                self.search_tree.insert(
                    root_id, "end", iid=item_id, text=row["relative_path"],
                    values=(human_bytes(row["size"]), row["cassette_number"], row["copied_at"]),
                )
        self.search_result_var.set(f"Risultati offline: {len(rows)}")
        if not rows:
            self.explorer_detail_title.set("Nessun file corrisponde alla ricerca.")
            self._set_explorer_details(
                "Modifica il testo cercato, scegli un'altra libreria oppure abilita le versioni storiche."
            )

    def _search_details(self) -> None:
        selected = self.search_tree.selection()
        if not selected:
            messagebox.showinfo("Ricerca file", "Selezionare un risultato.", parent=self)
            return
        self._show_explorer_node_details(selected[0])

    def _reset_backup_explorer(self, libraries: list[dict] | None = None) -> None:
        if not hasattr(self, "search_tree"):
            return
        available = libraries if libraries is not None else self._snapshot.get("libraries", [])
        self._explorer_mode = "tree"
        self._explorer_library_signature = explorer_library_signature(available)
        self.search_tree.delete(*self.search_tree.get_children())
        self._search_rows = {}
        self._explorer_nodes = {}
        self.search_query.set("")
        for library in available:
            library_id = library["id"]
            item_id = f"library::{library_id}"
            state = "Attiva" if library["status"] == "active" else "Ritirata"
            self.search_tree.insert(
                "", "end", iid=item_id,
                text=f"{library['name']}  [{library_id}]",
                values=("", "", state),
            )
            self._explorer_nodes[item_id] = {
                "kind": "library",
                "library_id": library_id,
                "name": library["name"],
                "source_root": library["source_root"],
                "status": library["status"],
                "loaded": False,
            }
            self._insert_explorer_placeholder(item_id)
        self.search_result_var.set("Archivio catalogato")
        self.explorer_detail_title.set("Seleziona un file nell'albero.")
        self._set_explorer_details(
            "Apri una libreria e naviga le cartelle. La lettura usa soltanto il catalogo locale SQLite."
        )

    def _insert_explorer_placeholder(self, parent_id: str) -> None:
        self.search_tree.insert(parent_id, "end", text="Caricamento...", tags=("placeholder",))

    def _explorer_open(self, _event=None) -> None:
        item_id = self.search_tree.focus()
        node = self._explorer_nodes.get(item_id)
        if not node or node.get("kind") not in ("library", "directory") or node.get("loaded"):
            return
        node["loaded"] = True
        library_id = node["library_id"]
        parent_path = "" if node["kind"] == "library" else node["relative_path"]
        self._run_task(
            "Apertura catalogo offline",
            lambda: self.application.browse_backup_children(library_id, parent_path),
            lambda rows, parent=item_id: self._populate_explorer_children(parent, rows),
            show_success=False,
            on_failure=lambda _error, parent=item_id: self._reset_explorer_node_after_failure(parent),
        )

    def _reset_explorer_node_after_failure(self, item_id: str) -> None:
        node = self._explorer_nodes.get(item_id)
        if not node or not self.search_tree.exists(item_id):
            return
        node["loaded"] = False
        if not self.search_tree.get_children(item_id):
            self._insert_explorer_placeholder(item_id)

    def _populate_explorer_children(self, parent_id: str, rows: list[dict]) -> None:
        if not self.search_tree.exists(parent_id):
            return
        self.search_tree.delete(*self.search_tree.get_children(parent_id))
        for row in rows:
            if row["kind"] == "directory":
                item_id = f"dir::{row['library_id']}::{row['relative_path']}"
                node = dict(row)
                node["loaded"] = False
                self._explorer_nodes[item_id] = node
                self.search_tree.insert(parent_id, "end", iid=item_id, text=row["name"])
                self._insert_explorer_placeholder(item_id)
            else:
                item_id = f"file::{row['id']}"
                self._explorer_nodes[item_id] = row
                self.search_tree.insert(
                    parent_id, "end", iid=item_id, text=row["name"],
                    values=(human_bytes(row["size"]), row["cassette_number"], row["copied_at"]),
                )
        if not rows:
            self.search_tree.insert(parent_id, "end", text="Nessun file catalogato", tags=("placeholder",))

    def _explorer_selected(self, _event=None) -> None:
        selected = self.search_tree.selection()
        if selected:
            self._show_explorer_node_details(selected[0])

    def _show_explorer_node_details(self, item_id: str) -> None:
        row = self._explorer_nodes.get(item_id)
        if not row:
            return
        kind = row.get("kind")
        if kind == "library":
            self.explorer_detail_title.set(f"{row['name']}  [{row['library_id']}]")
            self._set_explorer_details(
                f"TIPO\nLibreria di backup\n\nSTATO\n{self._status(row['status'])}\n\n"
                f"SORGENTE REGISTRATA\n{row['source_root']}\n\n"
                "La navigazione del backup non accede a questa sorgente e non richiede cassette."
            )
            return
        if kind == "directory":
            self.explorer_detail_title.set(row["name"])
            self._set_explorer_details(
                f"TIPO\nCartella ricostruita dal catalogo\n\nLIBRERIA\n{row['library_id']}\n\n"
                f"PERCORSO\n{row['relative_path']}"
            )
            return
        if kind != "file":
            return
        self.explorer_detail_title.set(row["relative_path"])
        self._set_explorer_details(self._format_file_details(row))

    def _format_file_details(self, row: dict) -> str:
        def timestamp_ns(value) -> str:
            if value is None:
                return "Non registrata"
            return datetime.fromtimestamp(int(value) / 1_000_000_000).astimezone().strftime(
                "%Y-%m-%d %H:%M:%S %Z"
            )

        streams = row.get("alternate_streams") or []
        stream_text = "Nessuno"
        if streams:
            stream_text = "\n".join(
                f"{stream.get('name', '?')}  ({human_bytes(int(stream.get('size', 0)))})"
                for stream in streams
            )
        state = row.get("state_label") or ("Corrente" if row.get("is_current", 1) else "Storica")
        mode = row.get("source_mode")
        mode_text = f"0o{int(mode):o}" if mode is not None else "Non registrata"
        metadata_state = {
            "complete": "Completi",
            "partial": "Parziali",
            "legacy": "Da acquisire con una scansione SMB",
        }.get(row.get("metadata_state"), "Non registrati")
        extension = PurePosixPath(row["relative_path"]).suffix or "(nessuna)"
        return (
            f"IDENTITA\n"
            f"Nome: {row.get('file_name') or PurePosixPath(row['relative_path']).name}\n"
            f"Estensione: {extension}\n"
            f"Percorso: {row['relative_path']}\n"
            f"Libreria: {row.get('library_name', row['library_id'])} [{row['library_id']}]\n"
            f"Versione: {state}\n\n"
            f"FILE ORIGINALE\n"
            f"Dimensione: {human_bytes(int(row['size']))} ({row['size']} byte)\n"
            f"Modificato: {timestamp_ns(row.get('mtime_ns'))}\n"
            f"Creato: {timestamp_ns(row.get('created_ns'))}\n"
            f"Ultimo accesso: {timestamp_ns(row.get('accessed_ns'))}\n"
            f"Attributi Windows: {describe_windows_attributes(row.get('windows_attributes'))}\n"
            f"Modalita: {mode_text}\n\n"
            f"SICUREZZA\n"
            f"Proprietario: {row.get('owner_name') or 'Non registrato'}\n"
            f"SID proprietario: {row.get('owner_sid') or 'Non registrato'}\n"
            f"Descrittore owner/group/DACL:\n{row.get('security_descriptor') or 'Non registrato'}\n\n"
            f"FLUSSI ALTERNATIVI NTFS\n{stream_text}\n\n"
            f"POSIZIONE NELL'ARCHIVIO\n"
            f"Numero cassetta: {row['cassette_number']}\n"
            f"ID nastro: {row['tape_id']}\n"
            f"Etichetta LTFS: {row.get('volume_label', '')}\n"
            f"Seriale volume: {row.get('volume_serial', '')}\n"
            f"Blocco: {row['block_id']}\n"
            f"Percorso LTFS: {row['tape_relative_path']}\n"
            f"Copiato: {row['copied_at']}\n"
            f"SHA-256: {row['sha256']}\n\n"
            f"QUALITA METADATI\n{metadata_state}"
            + (f"\nNota: {row['metadata_error']}" if row.get("metadata_error") else "")
        )

    def _set_explorer_details(self, text: str) -> None:
        self.explorer_details.configure(state="normal")
        self.explorer_details.delete("1.0", "end")
        self.explorer_details.insert("1.0", text)
        self.explorer_details.configure(state="disabled")

    def _doctor_backup(self) -> None:
        tape, mount = self.backup_tape.get().strip(), self.backup_mount.get().strip()
        self._run_task("Controllo nastro", lambda: self.application.doctor(tape, Path(mount)), self._doctor_result)

    def _doctor_result(self, result: dict) -> None:
        volume = result["volume"]
        messagebox.showinfo(
            "Controllo completato",
            f"Catalogo: {result['integrity']}\nFilesystem: {volume['filesystem']}\n"
            f"Nastro: {volume['tape_id']} · Cassetta: {volume['cassette_number']} ({volume['label']})\n"
            f"Liberi: {volume['free_human']}\n"
            f"Margine applicativo: {volume['reserve_human']}\nUtilizzabili dal programma: {volume['usable_human']}",
            parent=self,
        )

    def _start_backup(self) -> None:
        library = self.backup_library.get().strip()
        tape = self.backup_tape.get().strip()
        mount = self.backup_mount.get().strip()
        if not library or not tape or not mount:
            messagebox.showwarning("Dati mancanti", "Selezionare libreria, nastro e mount LTFS.", parent=self)
            return
        if not messagebox.askyesno(
            "Avviare il backup?",
            f"Libreria: {library}\nNastro: {tape}\nMount: {mount}\n\n"
            "I file saranno copiati direttamente sul nastro in un nuovo blocco.",
            parent=self,
        ):
            return
        self.progress_tracker.reset()
        self.progress_bar["value"] = 0
        self.footer_progress["value"] = 0
        self._run_task(
            "Backup in corso",
            lambda: self.application.backup(library, tape, Path(mount), progress=self._enqueue_progress),
            self._backup_complete,
        )

    def _backup_complete(self, result: dict) -> None:
        self.progress_bar["value"] = 100
        self.footer_progress["value"] = 100
        if result["status"] == "nothing-to-copy":
            messagebox.showinfo("Backup", "Nessun file nuovo o modificato da copiare.", parent=self)
        else:
            remaining = ""
            if result["remaining_files"]:
                remaining = (
                    f"\n\nRestano: {result['remaining_files']} file / {result['remaining_human']}"
                    f"\nCassette successive stimate: {result['estimated_remaining_tapes']}"
                )
            messagebox.showinfo(
                "Backup completato",
                f"Blocco: {result['block_id']}\nFile: {result['copied_files']}\nDati: {result['copied_human']}{remaining}",
                parent=self,
            )
        self.refresh()

    def _restore_plan(self) -> None:
        library = self.restore_library.get().strip()
        if not library:
            messagebox.showwarning("Dati mancanti", "Selezionare una libreria.", parent=self)
            return
        self._run_task("Piano di ripristino", lambda: self.application.restore_plan(library), self._show_restore_plan)

    def _show_restore_plan(self, plan: list[dict]) -> None:
        self._replace_tree(
            self.restore_plan_tree,
            ((index, row["tape_id"], row["file_count"], row["human"]) for index, row in enumerate(plan, 1)),
        )
        if not plan:
            messagebox.showinfo("Piano di ripristino", "Nessun file corrente nel catalogo.", parent=self)

    def _start_restore(self) -> None:
        library = self.restore_library.get().strip()
        tape = self.restore_tape.get().strip()
        mount = self.restore_mount.get().strip()
        destination = self.restore_destination.get().strip()
        if not all((library, tape, mount, destination)):
            messagebox.showwarning("Dati mancanti", "Compilare libreria, nastro, mount e destinazione.", parent=self)
            return
        if not messagebox.askyesno(
            "Avviare il ripristino?",
            f"Saranno ripristinati dal nastro {tape} i file correnti della libreria {library}.\n\nDestinazione: {destination}",
            parent=self,
        ):
            return
        overwrite = self.restore_overwrite.get()
        self.progress_tracker.reset()
        self.progress_bar["value"] = 0
        self.footer_progress["value"] = 0
        self._run_task(
            "Ripristino in corso",
            lambda: self.application.restore(
                library,
                tape,
                Path(mount),
                Path(destination),
                overwrite=overwrite,
                progress=self._enqueue_progress,
            ),
            lambda result: messagebox.showinfo(
                "Ripristino completato",
                f"File ripristinati: {result['restored_files']}\nDati: {result['restored_human']}",
                parent=self,
            ),
        )

    def _catalog_check(self) -> None:
        self._run_task("Controllo catalogo", self.application.catalog_check, self._catalog_check_result)

    def _catalog_check_result(self, result: dict) -> None:
        ok = (
            result["integrity"] == "ok"
            and not result["foreign_key_errors"]
            and not result["pending_blocks"]
            and not result["missing_cassette_numbers"]
        )
        messagebox.showinfo(
            "Integrità catalogo",
            f"Versione catalogo: {result['schema_version']}\nIntegrità SQLite: {result['integrity']}\n"
            f"Errori riferimenti: {len(result['foreign_key_errors'])}\n"
            f"Nastri senza numero cassetta: {result['missing_cassette_numbers']}\n"
            f"Blocchi rimasti in copia: {len(result['pending_blocks'])}\n\n{'Catalogo integro.' if ok else 'Controllare i dettagli prima di un backup.'}",
            parent=self,
        )

    def _export_catalog(self) -> None:
        destination = filedialog.asksaveasfilename(
            parent=self,
            title="Esporta catalogo",
            defaultextension=".json",
            filetypes=(("Catalogo JSON", "*.json"), ("Tutti i file", "*.*")),
            initialfile="lto-catalog.json",
        )
        if destination:
            self._run_task(
                "Esportazione catalogo",
                lambda: self.application.export_catalog(Path(destination)),
                lambda _result: messagebox.showinfo("Catalogo esportato", destination, parent=self),
            )

    def _forget_block(self) -> None:
        block_id = self._selected_id(self.blocks_tree, "un blocco")
        if not block_id:
            return
        if not messagebox.askyesno(
            "Dimenticare il blocco?",
            f"Il blocco {block_id} sarà nascosto dal catalogo.\n\nI file fisici resteranno sul nastro e lo spazio non sarà recuperato.",
            icon="warning",
            parent=self,
        ):
            return
        self._run_task(
            "Rimozione logica blocco",
            lambda: self.application.forget_block(block_id),
            lambda _result: self.refresh(),
        )

    def _tape_selected(self, _event=None) -> None:
        self._set_mount_for_tape(self.backup_tape.get(), self.backup_mount)

    def _restore_tape_selected(self, _event=None) -> None:
        self._set_mount_for_tape(self.restore_tape.get(), self.restore_mount)

    def _set_mount_for_tape(self, tape_id: str, variable: tk.StringVar) -> None:
        row = next((item for item in self._snapshot.get("tapes", []) if item["id"] == tape_id), None)
        if row and row.get("mount_hint"):
            variable.set(row["mount_hint"])

    def _browse_to(self, variable: tk.StringVar) -> None:
        selected = filedialog.askdirectory(parent=self, title="Seleziona cartella")
        if selected:
            variable.set(selected)

    def _run_task(
        self,
        label: str,
        action: Callable[[], object],
        on_success: Callable[[object], None] | None = None,
        show_success: bool = True,
        on_failure: Callable[[Exception], None] | None = None,
    ) -> None:
        if self._busy:
            messagebox.showinfo("Operazione in corso", "Attendere il completamento dell'operazione corrente.", parent=self)
            return
        self._set_busy(True, label)

        def worker() -> None:
            try:
                result = action()
                self._events.put(("result", label, result, on_success, show_success))
            except Exception as exc:
                self._events.put(("error", label, exc, traceback.format_exc(), on_failure))

        threading.Thread(target=worker, name="lto-gui-worker", daemon=True).start()

    def _enqueue_progress(self, event: dict) -> None:
        self._events.put(("progress", event))

    def _poll_events(self) -> None:
        try:
            while True:
                event = self._events.get_nowait()
                if event[0] == "progress":
                    self._handle_progress(event[1])
                elif event[0] == "result":
                    _, label, result, callback, show_success = event
                    self._set_busy(False, f"{label} completato")
                    try:
                        if callback:
                            callback(result)
                        elif show_success:
                            messagebox.showinfo("Operazione completata", label, parent=self)
                    except Exception as callback_error:
                        self._append_log(traceback.format_exc())
                        messagebox.showerror("Errore interfaccia", str(callback_error), parent=self)
                elif event[0] == "error":
                    _, label, error, detail, failure_callback = event
                    self._set_busy(False, f"{label} fallito")
                    if failure_callback:
                        try:
                            failure_callback(error)
                        except Exception:
                            self._append_log(traceback.format_exc())
                    if label == "Job automatico":
                        self._automatic_writing = False
                        self.automatic_stop_button.configure(state="disabled")
                        self.automatic_state.set(f"Job arrestato in sicurezza: {error}")
                        self.after(100, self.refresh)
                    self._append_log(detail)
                    title = "Operazione non completata" if isinstance(error, LtoBackupError) else "Errore imprevisto"
                    messagebox.showerror(title, str(error), parent=self)
        except queue.Empty:
            pass
        self._update_automatic_speed_idle()
        self.after(100, self._poll_events)

    def _handle_progress(self, event: dict) -> None:
        if event.get("event") == "tape.telemetry":
            self._apply_automatic_telemetry_event(event)
            return
        if event.get("job_id") and event.get("event") == "file.activity":
            self._apply_automatic_copy_activity(event)
            return
        if event.get("job_id") and str(event.get("event", "")).startswith(
            "batch.finalize."
        ):
            # Compatibility only: 0.11.24+ closes every file inside CopyFileEx.
            # Legacy batch-close telemetry must not replace cassette finalization.
            return
        if event.get("job_id") and event.get("event") == "unmount.progress":
            self._apply_automatic_finalization_event(event)
            self._apply_automatic_unmount_timing(event)
            return
        if str(event.get("event", "")).startswith("automatic."):
            self._automatic_activity_event = None
            self._automatic_activity_started_at = None
            self._automatic_writing = event.get("event") == "automatic.writing"
            if event.get("event") == "automatic.writing":
                self._automatic_timing_event = None
                self._automatic_timing_updated_at = None
                self._render_automatic_timing({})
            descriptions = {
                "automatic.waiting_media": "Inserire la cassetta {physical_label}. Attesa senza timeout.",
                "automatic.formatting": "Formattazione LTFS e assegnazione etichetta {physical_label}...",
                "automatic.mounting": "Mount LTFS della cassetta {physical_label}...",
                "automatic.writing": "Scrittura della cassetta {physical_label}...",
                "automatic.unmounting": "Chiusura indice ed espulsione di {physical_label}...",
                "automatic.ejected": "Cassetta {physical_label} completata ed espulsa.",
                "automatic.paused": "Job in pausa; la cassetta corrente ripartira da zero.",
                "automatic.completed": "Job automatico completato.",
                "automatic.failed": "Job automatico fallito: {error}",
                "automatic.append_full": "Cassetta APPEND {physical_label} piena; passaggio al supporto successivo.",
            }
            if event.get("operation") == "append":
                descriptions.update({
                    "automatic.waiting_media": (
                        "Inserire la cassetta {physical_label} per APPEND; nessuna formattazione. "
                        "Attesa senza timeout."
                    ),
                    "automatic.mounting": (
                        "Mount LTFS in APPEND di {physical_label}; dati esistenti protetti..."
                    ),
                    "automatic.writing": "Scrittura APPEND su {physical_label}...",
                    "automatic.unmounting": "Chiusura APPEND ed espulsione di {physical_label}...",
                    "automatic.paused": (
                        "Job in pausa; il nuovo ciclo APPEND verra riprovato senza formattazione."
                    ),
                })
            template = descriptions.get(event.get("event"), str(event.get("event")))
            try:
                message = template.format(**event)
            except (KeyError, ValueError):
                message = template
            self.automatic_state.set(message)
            self._apply_automatic_live_event(event, message)
            self.operation_var.set(message)
            self.status_var.set(message)
            self._append_log(message)
            return
        if event.get("job_id") and event.get("event") in {
            "tape.capacity", "file.start", "file.progress", "file.complete"
        }:
            self._apply_automatic_copy_event(event)
        view = self.progress_tracker.update(event)
        if event.get("job_id") and event.get("event") in {
            "batch.scan.start", "batch.scan.complete"
        }:
            self.automatic_state.set(view.message)
            self.automatic_selected_job_action.set(view.message)
            self.automatic_write_speed.set("Preparazione sorgenti: nessuna scrittura ancora")
        self.progress_bar["value"] = view.percent
        self.footer_progress["value"] = view.percent
        if event.get("event") in {"library.scan.start", "library.scan.complete"}:
            self.library_scan_progress["value"] = view.percent
            self.scan_result_var.set(view.message)
        self.operation_var.set(view.message)
        self.status_var.set(view.message)
        if event.get("event") in {
            "plan", "file.complete", "restore.complete", "block.complete", "block.failed",
            "catalog.snapshot.warning", "library.scan.start", "library.scan.complete",
        }:
            self._append_log(view.message)

    def _apply_automatic_copy_event(self, event: dict) -> None:
        job_id = str(event.get("job_id") or "")
        if job_id != self._automatic_job_id:
            return
        if event.get("event") in {"file.start", "file.progress", "file.complete"}:
            self._automatic_activity_event = None
            self._automatic_activity_started_at = None
        label = str(event.get("physical_label") or "")
        relative_path = str(event.get("relative_path") or "")
        now = time.monotonic()
        raw_write_bps = float(event.get("write_bps") or 0.0)
        self._automatic_live_write_bps = smooth_live_write_bps(
            self._automatic_live_write_bps,
            raw_write_bps,
        )
        speed = write_speed_text(
            self._automatic_live_write_bps,
            float(event.get("average_write_bps") or 0.0),
            language=self.language,
        )
        self._automatic_last_write_at = now
        self._automatic_average_write_bps = float(event.get("average_write_bps") or 0.0)
        if hasattr(self, "automatic_speed_chart"):
            self.automatic_speed_chart.add_sample(
                now,
                self._automatic_average_write_bps,
                self._automatic_live_write_bps,
            )
        self._automatic_timing_event = dict(event)
        self._automatic_timing_updated_at = now
        self._render_automatic_timing(event)
        self.automatic_write_speed.set(speed)
        self.automatic_state.set(
            f"Scrittura {label}: {relative_path}" if relative_path else f"Scrittura {label}"
        )
        self.automatic_selected_job_action.set(
            f"Scrittura in corso: {label}  |  {speed}"
        )
        self.automatic_job_progress["value"] = float(
            event.get("job_progress_percent") or 0.0
        )
        self.automatic_summary_vars["copied"].set(
            human_bytes(int(event.get("job_copied_bytes") or 0))
        )
        capacity = tape_capacity_view(event, language=self.language)
        tape_title = self._t(
            "CASSETTA CORRENTE  |  capacita disponibile dopo il mount"
        ).split("|", 1)[0].strip()
        self.automatic_tape_capacity_title.set(f"{tape_title}  |  {label or '-'}")
        self.automatic_tape_capacity_progress["value"] = capacity["percent"]
        self.automatic_tape_remaining.set(capacity["remaining"])
        self.automatic_tape_ltfs_free.set(capacity["ltfs_free"])
        self.automatic_tape_policy.set(
            f"{capacity['limit']}  |  {capacity['reserve']}  |  {capacity['overhead']}"
        )

        for item_id in self.automatic_queue_tree.get_children():
            values = list(self.automatic_queue_tree.item(item_id, "values"))
            if len(values) <= 6 or values[1] != label:
                continue
            planned_files = values[4].split("/", 1)[-1].strip() if "/" in values[4] else "-"
            values[4] = f"{int(event.get('cassette_copied_files') or 0)} / {planned_files}"
            values[6] = human_bytes(int(event.get("cassette_copied_bytes") or 0))
            self.automatic_queue_tree.item(item_id, values=values, tags=("queue_current",))
            break

        if self.automatic_jobs_tree.exists(job_id):
            values = list(self.automatic_jobs_tree.item(job_id, "values"))
            if len(values) >= 4:
                checkpoint = values[3].split("(", 1)[0].rstrip()
                values[3] = (
                    f"{checkpoint}  ({float(event.get('job_progress_percent') or 0.0):.0f}%)"
                )
                self.automatic_jobs_tree.item(job_id, values=values, tags=("job_active",))

    def _apply_automatic_copy_activity(self, event: dict) -> None:
        job_id = str(event.get("job_id") or "")
        if job_id != self._automatic_job_id:
            return
        phase = str(event.get("phase") or "")
        if phase.endswith(".complete"):
            if (
                phase == "timing.complete"
                and float(event.get("close_elapsed_seconds") or 0.0)
                >= LTFS_SLOW_CLOSE_SECONDS
            ):
                self._append_log(
                    "Chiusura LTFS lenta: "
                    f"{event.get('relative_path') or '-'}  |  "
                    f"{float(event.get('close_elapsed_seconds') or 0.0):.2f}s  |  "
                    f"soglia {LTFS_SLOW_CLOSE_SECONDS:.0f}s"
                )
            self._automatic_timing_event = dict(event)
            self._automatic_timing_updated_at = time.monotonic()
            self._automatic_average_write_bps = float(
                event.get("average_write_bps") or 0.0
            )
            self._render_automatic_timing(event)
            self._automatic_activity_event = None
            self._automatic_activity_started_at = None
            telemetry = getattr(self, "_automatic_telemetry_text", "")
            if telemetry:
                self.automatic_ltfs_activity.set(telemetry)
            return
        if not phase.endswith(".pending"):
            return
        self._automatic_activity_event = dict(event)
        now = time.monotonic()
        self._automatic_activity_started_at = now
        self._automatic_timing_event = dict(event)
        self._automatic_timing_updated_at = now
        self._automatic_average_write_bps = float(event.get("average_write_bps") or 0.0)
        self._render_automatic_timing(event)
        text = copy_activity_text(event, 0, language=self.language)
        self.automatic_state.set(text)
        self.automatic_selected_job_action.set(text)
        self.automatic_ltfs_activity.set(text)

    def _apply_automatic_unmount_timing(self, event: dict) -> None:
        job_id = str(event.get("job_id") or "")
        if job_id and job_id != self._automatic_job_id:
            return
        if event.get("cassette_elapsed_seconds") is None:
            return
        now = time.monotonic()
        self._automatic_timing_event = dict(event)
        self._automatic_timing_updated_at = now
        self._automatic_average_write_bps = float(
            event.get("average_write_bps") or 0.0
        )
        self._render_automatic_timing(event)
        stalled = (
            int(now - self._automatic_last_write_at)
            if self._automatic_last_write_at is not None else None
        )
        self.automatic_write_speed.set(
            write_speed_text(
                None,
                self._automatic_average_write_bps,
                stalled_seconds=stalled,
                language=self.language,
            )
        )
        if hasattr(self, "automatic_speed_chart"):
            self.automatic_speed_chart.add_sample(
                now,
                self._automatic_average_write_bps,
                None,
            )

    def _set_automatic_finalization_active(self, active: bool) -> None:
        requested = bool(active)
        if getattr(self, "_automatic_finalization_active", None) is requested:
            return
        self._automatic_finalization_active = requested
        self.automatic_finalize_panel.configure(height=166 if requested else 64)
        if requested:
            self.automatic_finalize_detail_field.pack(fill="x")
            self.automatic_finalize_progress.pack(fill="x", pady=(4, 6))
            self.automatic_finalize_metrics.pack(fill="x")
        else:
            self.automatic_finalize_detail_field.pack_forget()
            self.automatic_finalize_progress.pack_forget()
            self.automatic_finalize_metrics.pack_forget()

    def _apply_automatic_finalization_event(self, event: dict) -> None:
        job_id = str(event.get("job_id") or "")
        if job_id and job_id != self._automatic_job_id:
            return
        self._set_automatic_finalization_active(True)
        view = finalization_view(event, language=self.language)
        self.automatic_finalize_phase.set(view["phase"])
        self.automatic_finalize_detail.set(view["detail"])
        self.automatic_finalize_counter.set(view["counter"])
        self.automatic_finalize_elapsed.set(view["elapsed"])
        self.automatic_finalize_eta.set(view["eta"])
        self.automatic_finalize_progress["value"] = view["percent"]
        self._automatic_finalization_event = dict(event)
        self._automatic_finalization_updated_at = time.monotonic()

    def _apply_automatic_telemetry_event(self, event: dict) -> None:
        job_id = str(event.get("job_id") or "")
        if job_id != self._automatic_job_id:
            return
        text = tape_activity_text(event, language=self.language)
        self.automatic_ltfs_activity.set(text)
        activity = str(event.get("activity") or "")
        if text != self._automatic_telemetry_text and activity in {"alert", "unavailable"}:
            self._append_log(text)
        self._automatic_telemetry_text = text

    def _update_automatic_speed_idle(self) -> None:
        if (
            getattr(self, "_automatic_finalization_event", None) is not None
            and getattr(self, "_automatic_finalization_updated_at", None) is not None
        ):
            now = time.monotonic()
            advanced = dict(self._automatic_finalization_event)
            elapsed = max(
                0.0,
                float(advanced.get("elapsed_seconds") or 0.0)
                + now - self._automatic_finalization_updated_at,
            )
            advanced["elapsed_seconds"] = elapsed
            view = finalization_view(advanced, language=self.language)
            self.automatic_finalize_phase.set(view["phase"])
            self.automatic_finalize_detail.set(view["detail"])
            self.automatic_finalize_counter.set(view["counter"])
            self.automatic_finalize_elapsed.set(view["elapsed"])
            self.automatic_finalize_eta.set(view["eta"])
            self.automatic_finalize_progress["value"] = view["percent"]
        if (
            self._automatic_activity_event is not None
            and self._automatic_activity_started_at is not None
        ):
            now = time.monotonic()
            elapsed = int(now - self._automatic_activity_started_at)
            text = copy_activity_text(
                self._automatic_activity_event,
                elapsed,
                language=self.language,
            )
            self.automatic_state.set(text)
            self.automatic_selected_job_action.set(text)
            self.automatic_ltfs_activity.set(text)
            timing = advance_write_timing(self._automatic_activity_event, elapsed)
            self._automatic_average_write_bps = float(
                timing.get("average_write_bps") or 0.0
            )
            self._render_automatic_timing(timing)
            stalled = (
                int(now - self._automatic_last_write_at)
                if self._automatic_last_write_at is not None else elapsed
            )
            self.automatic_write_speed.set(
                write_speed_text(
                    getattr(self, "_automatic_live_write_bps", None),
                    self._automatic_average_write_bps,
                    stalled_seconds=stalled,
                    language=self.language,
                )
            )
            if hasattr(self, "automatic_speed_chart"):
                self.automatic_speed_chart.add_sample(
                    now,
                    self._automatic_average_write_bps,
                    None,
                )
            return
        if not self._automatic_writing or self._automatic_last_write_at is None:
            return
        stalled = int(time.monotonic() - self._automatic_last_write_at)
        if (
            self._automatic_timing_event is not None
            and self._automatic_timing_updated_at is not None
        ):
            timing = advance_write_timing(
                self._automatic_timing_event,
                time.monotonic() - self._automatic_timing_updated_at,
            )
            self._automatic_average_write_bps = float(
                timing.get("average_write_bps") or 0.0
            )
            self._render_automatic_timing(timing)
        if stalled < 3:
            return
        self.automatic_write_speed.set(
            write_speed_text(
                getattr(self, "_automatic_live_write_bps", None),
                self._automatic_average_write_bps,
                stalled_seconds=stalled,
                language=self.language,
            )
        )
        if hasattr(self, "automatic_speed_chart"):
            self.automatic_speed_chart.add_sample(
                time.monotonic(),
                self._automatic_average_write_bps,
                None,
            )

    def _render_automatic_timing(self, event: dict) -> None:
        view = write_timing_view(event, language=self.language)
        self.automatic_elapsed_time.set(view["elapsed"])
        self.automatic_tape_eta.set(view["tape_eta"])
        self.automatic_job_eta.set(view["job_eta"])

    def _apply_automatic_live_event(self, event: dict, message: str) -> None:
        """Keep the selected job rail current while the worker owns the catalog."""

        if not hasattr(self, "automatic_selected_job_action"):
            return
        job_id = str(event.get("job_id") or "")
        if job_id and job_id != self._automatic_job_id:
            return
        kind = str(event.get("event") or "")
        self.automatic_selected_job_action.set(message)
        status = {
            "automatic.waiting_media": "Attesa cassetta",
            "automatic.formatting": "Formattazione",
            "automatic.mounting": "Mount LTFS",
            "automatic.writing": "Scrittura",
            "automatic.unmounting": "Finalizzazione cassetta",
            "automatic.ejected": "Cassetta conclusa",
            "automatic.paused": "In pausa",
            "automatic.completed": "Completato",
            "automatic.failed": "Fallito",
        }.get(kind)
        if status:
            self.automatic_summary_vars["status"].set(status)

        label = str(event.get("physical_label") or "")
        target_item = None
        for item_id in self.automatic_queue_tree.get_children():
            values = self.automatic_queue_tree.item(item_id, "values")
            if len(values) > 1 and values[1] == label:
                target_item = item_id
                break
        if target_item is None and kind == "automatic.failed":
            target_item = next(
                (
                    item_id for item_id in self.automatic_queue_tree.get_children()
                    if "queue_current" in self.automatic_queue_tree.item(item_id, "tags")
                ),
                None,
            )
        if target_item:
            values = list(self.automatic_queue_tree.item(target_item, "values"))
            suffix = values[0].split("]", 1)[-1]
            if kind == "automatic.ejected":
                values[0] = f"[OK]{suffix}"
                values[3] = "Completata ed espulsa"
                self.automatic_queue_tree.item(target_item, values=values, tags=("queue_done",))
            else:
                values[0] = f"[ORA]{suffix}"
                values[3] = status or values[3]
                tag = "queue_failed" if kind == "automatic.failed" else "queue_current"
                self.automatic_queue_tree.item(target_item, values=values, tags=(tag,))

        active_items = [
            item_id for item_id in self.automatic_queue_tree.get_children()
            if "queue_reserved" not in self.automatic_queue_tree.item(item_id, "tags")
        ]
        reserved = len(self.automatic_queue_tree.get_children()) - len(active_items)
        total = len(active_items)
        completed = sum(
            "queue_done" in self.automatic_queue_tree.item(item_id, "tags")
            for item_id in active_items
        )
        if total:
            self.automatic_summary_vars["cassettes"].set(
                f"{completed} / {total}" + (f"  +{reserved}R" if reserved else "")
            )
            if kind in {"automatic.ejected", "automatic.completed"}:
                self.automatic_job_progress["value"] = completed * 100.0 / total

        if job_id and self.automatic_jobs_tree.exists(job_id):
            values = list(self.automatic_jobs_tree.item(job_id, "values"))
            if len(values) >= 5:
                if status:
                    values[2] = status
                if total:
                    values[3] = (
                        f"{completed} / {total}  ({completed * 100.0 / total:.0f}%)"
                        + (f"  +{reserved}R" if reserved else "")
                    )
                if label and kind != "automatic.ejected":
                    values[4] = label
                if kind == "automatic.completed":
                    values[4] = "-"
                job_tag = (
                    "job_completed" if kind == "automatic.completed"
                    else "job_failed" if kind == "automatic.failed"
                    else "job_active"
                )
                self.automatic_jobs_tree.item(job_id, values=values, tags=(job_tag,))

    def _set_busy(self, busy: bool, label: str) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for button in self._action_buttons:
            try:
                button.configure(state=state)
            except tk.TclError:
                pass
        if not busy and hasattr(self, "inventory_use_button"):
            can_use_plan = bool(
                self._inventory_plan and self._inventory_plan.get("estimated_tapes")
            )
            self.inventory_use_button.configure(state="normal" if can_use_plan else "disabled")
        self.status_var.set(label)
        self.header_state_dot.configure(fg=self.ACCENT if busy else self.SUCCESS)
        self.header_state.configure(text=f" {label}", fg=self.TEXT)

    def _append_log(self, message: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message.rstrip() + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _close(self) -> None:
        if self._busy:
            messagebox.showinfo(
                "Operazione in corso",
                "Attendere il completamento dell'operazione prima di chiudere la finestra.",
                parent=self,
            )
            return
        self.destroy()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--state-dir", type=Path, default=default_state_dir())
    parser.add_argument("--version", action="version", version=f"LTO Archiver {__version__}")
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--page",
        choices=[item.key for item in NAVIGATION_ITEMS],
        default="overview",
        help=argparse.SUPPRESS,
    )
    return parser


def _write_windows_stdout(text: str) -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_std_handle = kernel32.GetStdHandle
        get_std_handle.argtypes = [wintypes.DWORD]
        get_std_handle.restype = wintypes.HANDLE
        write_file = kernel32.WriteFile
        write_file.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        write_file.restype = wintypes.BOOL

        handle = get_std_handle(wintypes.DWORD(0xFFFFFFF5))
        if handle in (None, 0, ctypes.c_void_p(-1).value):
            return False
        payload = text.encode("utf-8")
        buffer = ctypes.create_string_buffer(payload)
        written = wintypes.DWORD()
        succeeded = write_file(
            handle,
            ctypes.cast(buffer, ctypes.c_void_p),
            len(payload),
            ctypes.byref(written),
            None,
        )
        return bool(succeeded) and written.value == len(payload)
    except (AttributeError, OSError, ValueError):
        return False


def _write_version_stream(stream: TextIO | None, text: str) -> bool:
    if stream is None:
        return False
    try:
        stream.write(text)
        stream.flush()
        return True
    except (AttributeError, OSError, ValueError):
        return False


def _emit_gui_version(
    *,
    stream: TextIO | None = None,
    native_writer: Callable[[str], bool] | None = None,
) -> bool:
    text = f"LTO Archiver {__version__}\n"
    target = sys.stdout if stream is None else stream
    if _write_version_stream(target, text):
        return True

    writer = _write_windows_stdout if native_writer is None else native_writer
    try:
        if writer(text):
            return True
    except (AttributeError, OSError, ValueError):
        pass

    for fallback in (getattr(sys, "__stdout__", None), getattr(sys, "stderr", None)):
        if fallback is not target and _write_version_stream(fallback, text):
            return True
    return False


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if "--version" in arguments:
        _emit_gui_version()
        return 0
    args = build_parser().parse_args(arguments)
    cfa_access = ensure_controlled_folder_access()
    application = LtoApplication(args.state_dir)
    try:
        application.ensure_initialized()
    except Exception as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("LTO Archiver", f"Impossibile inizializzare il programma:\n\n{exc}")
        root.destroy()
        return 1
    window = LtoBackupWindow(application)
    if cfa_access.status == "failed":
        window.after_idle(
            lambda: messagebox.showwarning(
                "Protezione Windows",
                "LTO Archiver non ha ottenuto l'autorizzazione Controlled Folder Access. "
                "Le funzioni dirette del drive potrebbero essere bloccate.\n\n"
                f"Dettaglio: {cfa_access.detail}",
                parent=window,
            )
        )
    window._show_page(args.page)
    smoke_errors: list[str] = []
    if args.smoke_test:
        def run_smoke_test() -> None:
            try:
                exercise_responsive_layouts(window)
            except BaseException:
                detail = traceback.format_exc()
                smoke_errors.append(detail)
                try:
                    args.state_dir.mkdir(parents=True, exist_ok=True)
                    (args.state_dir / "gui-smoke-error.txt").write_text(
                        detail, encoding="utf-8"
                    )
                finally:
                    window.destroy()

        window.after(250, run_smoke_test)
    window.mainloop()
    return 1 if smoke_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
