from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .automation import TapeTelemetrySnapshot, WindowsTapeDevice, classify_tape_activity
from .catalog import Catalog
from .engine import BackupEngine
from .errors import CapacityError, LtoBackupError, ValidationError
from .settings import (
    AppPaths,
    DEFAULT_RESERVE_BYTES,
    Settings,
    default_state_dir,
    load_settings,
    save_settings,
    upgrade_legacy_settings,
)
from .util import RunLock, human_bytes, write_json_atomic


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lto-backup",
        description="Backup append-only di librerie SMB su nastri LTFS, senza TAR.",
    )
    parser.add_argument("--state-dir", type=Path, default=default_state_dir())
    parser.add_argument("--json", action="store_true", help="Output macchina in JSON")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Inizializza configurazione e catalogo")
    init.add_argument(
        "--reserve-gib", type=int, default=DEFAULT_RESERVE_BYTES // 1024**3,
        help="Margine applicativo opzionale (predefinito: 0 GiB; usa lo spazio LTFS disponibile)",
    )
    init.add_argument("--buffer-mib", type=int, default=16)
    init.add_argument("--min-age-seconds", type=int, default=900)

    library = subparsers.add_parser("library", help="Gestione librerie")
    library_sub = library.add_subparsers(dest="library_command", required=True)
    library_add = library_sub.add_parser("add")
    library_add.add_argument("--id", required=True)
    library_add.add_argument("--name", required=True)
    library_add.add_argument("--source", required=True)
    library_list = library_sub.add_parser("list")
    library_list.add_argument("--all", action="store_true")
    library_delete = library_sub.add_parser("delete")
    library_delete.add_argument("--id", required=True)
    library_delete.add_argument("--confirm", required=True, help="Ripetere esattamente l'ID libreria")

    tape = subparsers.add_parser("tape", help="Gestione nastri LTFS")
    tape_sub = tape.add_subparsers(dest="tape_command", required=True)
    tape_register = tape_sub.add_parser("register")
    tape_register.add_argument("--id", required=True)
    tape_register.add_argument(
        "--cassette-number",
        help="Numero fisico della cassetta; se omesso coincide con --id",
    )
    tape_register.add_argument("--mount", type=Path, required=True)
    tape_sub.add_parser("list")

    scan = subparsers.add_parser("scan", help="Calcola il prossimo blocco senza scrivere")
    scan.add_argument("--library", required=True)
    scan.add_argument("--min-age-seconds", type=int)

    backup = subparsers.add_parser("backup", help="Copia direttamente i file in un nuovo blocco LTFS")
    backup.add_argument("--library", required=True)
    backup.add_argument("--tape", required=True)
    backup.add_argument("--mount", type=Path, required=True)
    backup.add_argument("--min-age-seconds", type=int)
    backup.add_argument("--dry-run", action="store_true")
    backup.add_argument("--json-progress", action="store_true")

    block = subparsers.add_parser("block", help="Gestione blocchi di backup")
    block_sub = block.add_subparsers(dest="block_command", required=True)
    block_list = block_sub.add_parser("list")
    block_list.add_argument("--library")
    block_list.add_argument("--all", action="store_true")
    block_forget = block_sub.add_parser("forget")
    block_forget.add_argument("--id", required=True)
    block_forget.add_argument("--confirm", required=True, help="Ripetere esattamente l'ID blocco")

    automatic = subparsers.add_parser(
        "automatic", help="Recupero amministrativo dei job automatici"
    )
    automatic_sub = automatic.add_subparsers(dest="automatic_command", required=True)
    automatic_reset = automatic_sub.add_parser(
        "reset-cassette",
        help="Azzera il tentativo della cassetta corrente dopo un'interruzione",
    )
    automatic_reset.add_argument("--job", required=True)
    automatic_reset.add_argument(
        "--confirm", required=True, help="Ripetere esattamente l'ID job"
    )

    restore = subparsers.add_parser("restore", help="Pianifica o ripristina una libreria")
    restore_sub = restore.add_subparsers(dest="restore_command", required=True)
    restore_plan = restore_sub.add_parser("plan")
    restore_plan.add_argument("--library", required=True)
    restore_run = restore_sub.add_parser("run")
    restore_run.add_argument("--library", required=True)
    restore_run.add_argument("--tape", required=True)
    restore_run.add_argument("--mount", type=Path, required=True)
    restore_run.add_argument("--destination", type=Path, required=True)
    restore_run.add_argument("--overwrite", action="store_true")
    restore_run.add_argument("--json-progress", action="store_true")

    doctor = subparsers.add_parser("doctor", help="Controlla catalogo e nastro montato")
    doctor.add_argument("--tape")
    doctor.add_argument("--mount", type=Path)

    telemetry = subparsers.add_parser(
        "telemetry", help="Legge una volta la telemetria SCSI senza modificare il nastro"
    )
    telemetry.add_argument("--device", default="TAPE0")

    catalog = subparsers.add_parser("catalog", help="Verifica o esporta il catalogo")
    catalog_sub = catalog.add_subparsers(dest="catalog_command", required=True)
    catalog_sub.add_parser("check")
    catalog_export = catalog_sub.add_parser("export")
    catalog_export.add_argument("--output", type=Path, required=True)
    return parser


def configure_logging(paths: AppPaths) -> None:
    paths.log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        paths.log_dir / "lto-backup.log",
        maxBytes=10 * 1024**2,
        backupCount=10,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler])


def emit(value: object, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, ensure_ascii=False, indent=2, default=str))
        return
    if isinstance(value, str):
        print(value)
    else:
        print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def progress_printer(json_progress: bool):
    def callback(event: dict) -> None:
        logging.info("progress %s", json.dumps(event, ensure_ascii=False, default=str))
        if json_progress:
            print(json.dumps(event, ensure_ascii=False, default=str), flush=True)
        elif event["event"] == "file.complete":
            print(
                f"[{event['index']}/{event['total_files']}] {event['relative_path']} - "
                f"{human_bytes(int(event['copied_bytes']))}",
                flush=True,
            )
        elif event["event"] == "restore.complete":
            print(f"[{event['index']}/{event['total_files']}] {event['relative_path']}", flush=True)

    return callback


def initialize(paths: AppPaths, args: argparse.Namespace) -> dict:
    settings = Settings(
        reserve_bytes=args.reserve_gib * 1024**3,
        buffer_bytes=args.buffer_mib * 1024**2,
        min_age_seconds=args.min_age_seconds,
    )
    with RunLock(paths.lock_file):
        save_settings(paths, settings)
        with Catalog(paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.event("application.init", {"version": __version__})
    return {
        "state_dir": str(paths.state_dir),
        "catalog": str(paths.catalog_file),
        "reserve_bytes": settings.reserve_bytes,
        "reserve_human": human_bytes(settings.reserve_bytes),
    }


def handle(paths: AppPaths, args: argparse.Namespace) -> object:
    if args.command == "init":
        return initialize(paths, args)
    if args.command == "telemetry":
        try:
            snapshot = WindowsTapeDevice(args.device).read_telemetry()
        except (LtoBackupError, OSError) as exc:
            snapshot = TapeTelemetrySnapshot(
                available=False,
                alert_query_available=False,
                detail=str(exc),
            )
        return {
            **asdict(snapshot),
            "activity": classify_tape_activity(snapshot, None),
            "device": args.device,
            "read_only": True,
        }

    with RunLock(paths.lock_file):
        settings = upgrade_legacy_settings(paths)
    configure_logging(paths)
    with Catalog(paths.catalog_file) as catalog:
        catalog.initialize()
        engine = BackupEngine(catalog, settings, paths)

        if args.command == "library":
            if args.library_command == "add":
                with RunLock(paths.lock_file):
                    catalog.add_library(args.id, args.name, args.source)
                return {"added": args.id, "source": args.source}
            if args.library_command == "list":
                return [dict(row) for row in catalog.list_libraries(args.all)]
            if args.library_command == "delete":
                if args.confirm != args.id:
                    raise ValidationError("Conferma errata: --confirm deve coincidere con --id")
                with RunLock(paths.lock_file):
                    result = catalog.delete_library(args.id)
                return {
                    "deleted": args.id,
                    **result,
                    "message": "Dati della libreria cancellati dal catalogo; sorgente SMB e nastri invariati.",
                }

        if args.command == "tape":
            if args.tape_command == "register":
                with RunLock(paths.lock_file):
                    cassette_number = args.cassette_number or args.id
                    volume = engine.register_tape(
                        args.id,
                        args.mount,
                        cassette_number=cassette_number,
                    )
                return {
                    "tape_id": args.id,
                    "cassette_number": cassette_number,
                    "mount": str(volume.root),
                    "label": volume.label,
                    "serial": volume.serial,
                    "filesystem": volume.filesystem,
                    "free_bytes": volume.free_bytes,
                }
            return [dict(row) for row in catalog.list_tapes()]

        if args.command == "scan":
            plan = engine.scan(args.library, args.min_age_seconds)
            return {
                "library_id": plan.library_id,
                "source_root": str(plan.source_root),
                "files": len(plan.items),
                "bytes": plan.total_bytes,
                "human": human_bytes(plan.total_bytes),
                "skipped_unchanged": plan.skipped_unchanged,
                "skipped_too_recent": plan.skipped_too_recent,
            }

        if args.command == "backup":
            with RunLock(paths.lock_file):
                result = engine.backup(
                    args.library,
                    args.tape,
                    args.mount,
                    min_age_seconds=args.min_age_seconds,
                    progress=progress_printer(args.json_progress),
                    dry_run=args.dry_run,
                )
            if result is None:
                return {"status": "nothing-to-copy", "library_id": args.library}
            return {
                "status": "dry-run" if args.dry_run else "completed",
                "block_id": result.block_id,
                "library_id": result.library_id,
                "tape_id": result.tape_id,
                "copied_files": result.copied_files,
                "copied_bytes": result.copied_bytes,
                "tape_relative_root": result.tape_relative_root,
                "remaining_files": result.remaining_files,
                "remaining_bytes": result.remaining_bytes,
                "estimated_remaining_tapes": result.estimated_remaining_tapes,
            }

        if args.command == "block":
            if args.block_command == "list":
                return [dict(row) for row in catalog.list_blocks(args.library, args.all)]
            if args.confirm != args.id:
                raise ValidationError("Conferma errata: --confirm deve coincidere con --id")
            with RunLock(paths.lock_file):
                catalog.forget_block(args.id)
            return {
                "forgotten": args.id,
                "tape_data_deleted": False,
                "message": "Blocco nascosto dal catalogo; i dati fisici restano sul nastro.",
            }

        if args.command == "automatic":
            if args.confirm != args.job:
                raise ValidationError("Conferma errata: --confirm deve coincidere con --job")
            job = catalog.get_automatic_job(args.job)
            sequence = int(job["current_sequence"])
            if sequence <= 0:
                raise ValidationError(f"Il job {args.job} non ha una cassetta corrente")
            with RunLock(paths.lock_file):
                discarded = catalog.reset_automatic_cassette(
                    args.job,
                    sequence,
                    "Ripristino amministrativo dopo interruzione del processo",
                )
            return {
                "job_id": args.job,
                "sequence": sequence,
                "status": "paused",
                "discarded": discarded,
                "message": "La cassetta corrente ripartira da zero e verra riformattata.",
            }

        if args.command == "restore":
            if args.restore_command == "plan":
                catalog.get_library(args.library, include_retired=True)
                return [
                    {
                        "tape_id": row["tape_id"],
                        "file_count": row["file_count"],
                        "total_bytes": row["total_bytes"],
                        "human": human_bytes(row["total_bytes"]),
                    }
                    for row in catalog.restore_plan(args.library)
                ]
            with RunLock(paths.lock_file):
                files, total_bytes = engine.restore(
                    args.library,
                    args.tape,
                    args.mount,
                    args.destination,
                    overwrite=args.overwrite,
                    progress=progress_printer(args.json_progress),
                )
            return {"restored_files": files, "restored_bytes": total_bytes, "human": human_bytes(total_bytes)}

        if args.command == "doctor":
            integrity = catalog.connection.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_keys = [dict(row) for row in catalog.connection.execute("PRAGMA foreign_key_check")]
            result: dict[str, object] = {
                "catalog_integrity": integrity,
                "foreign_key_errors": foreign_keys,
                "pending_blocks": [dict(row) for row in catalog.connection.execute(
                    "SELECT * FROM blocks WHERE status='copying' ORDER BY started_at"
                )],
            }
            if bool(args.tape) != bool(args.mount):
                raise ValidationError("Per controllare un nastro servono sia --tape sia --mount")
            if args.tape and args.mount:
                _, volume = engine.validate_tape(args.tape, args.mount)
                result["volume"] = {
                    "tape_id": args.tape,
                    "root": str(volume.root),
                    "filesystem": volume.filesystem,
                    "label": volume.label,
                    "serial": volume.serial,
                    "free_bytes": volume.free_bytes,
                    "reserve_bytes": settings.reserve_bytes,
                    "usable_bytes": max(0, volume.free_bytes - settings.reserve_bytes),
                }
            return result

        if args.command == "catalog":
            if args.catalog_command == "check":
                return {
                    "schema_version": int(
                        catalog.connection.execute(
                            "SELECT value FROM metadata WHERE key='schema_version'"
                        ).fetchone()[0]
                    ),
                    "integrity": catalog.connection.execute("PRAGMA integrity_check").fetchone()[0],
                    "foreign_key_errors": [
                        dict(row) for row in catalog.connection.execute("PRAGMA foreign_key_check")
                    ],
                    "missing_cassette_numbers": catalog.connection.execute(
                        "SELECT COUNT(*) FROM tapes "
                        "WHERE cassette_number IS NULL OR trim(cassette_number)=''"
                    ).fetchone()[0],
                    "uncommitted_visible_files": catalog.connection.execute(
                        """
                        SELECT COUNT(*) FROM file_versions fv
                        JOIN blocks b ON b.id=fv.block_id
                        WHERE fv.visible=1 AND b.status<>'completed'
                        """
                    ).fetchone()[0],
                }
            payload = catalog.export()
            write_json_atomic(args.output, payload)
            return {"exported": str(args.output)}

    raise ValidationError("Comando non gestito")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    paths = AppPaths(args.state_dir.resolve())
    try:
        result = handle(paths, args)
        emit(result, args.json)
        return 0
    except CapacityError as exc:
        logging.error("capacity error: %s", exc)
        print(f"ERRORE CAPACITÀ: {exc}", file=sys.stderr)
        return 3
    except LtoBackupError as exc:
        logging.error("operator error: %s", exc)
        print(f"ERRORE: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        logging.warning("operation interrupted")
        print("Operazione interrotta.", file=sys.stderr)
        return 130
    except Exception as exc:
        logging.exception("unexpected failure")
        print(f"ERRORE IMPREVISTO: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
