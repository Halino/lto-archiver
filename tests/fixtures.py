"""Sanitized catalogs used by migration contract tests."""

from __future__ import annotations

from pathlib import Path

from ltobackup.catalog import SCHEMA_VERSION, Catalog


def build_frozen_job_fixture(
    path: Path,
    *,
    completed: int = 3,
    total: int = 20,
    schema_version: int = 13,
    fourth_status: str = "pending",
    blocks_per_cassette: int = 1,
    library_ids: tuple[str, ...] = ("LIB1",),
) -> Path:
    """Create a synthetic, frozen 20-cassette job without real paths or media."""

    if schema_version not in range(13, SCHEMA_VERSION + 1):
        raise ValueError(
            f"schema_version must be between 13 and {SCHEMA_VERSION}"
        )
    if total < 4 or not 0 <= completed <= total:
        raise ValueError("fixture requires at least four cassettes")
    if blocks_per_cassette < 1:
        raise ValueError("fixture requires at least one block per cassette")
    if not library_ids or len({value.casefold() for value in library_ids}) != len(
        library_ids
    ):
        raise ValueError("fixture requires unique libraries")

    path = Path(path)
    cassettes = [
        (
            f"TAPE{sequence:02d}",
            f"SERIAL{sequence:02d}",
            blocks_per_cassette,
            sequence * blocks_per_cassette,
        )
        for sequence in range(1, total + 1)
    ]
    with Catalog(path) as catalog:
        if schema_version == 38:
            metadata_exists = catalog.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='metadata'"
            ).fetchone()
            existing_version = None
            if metadata_exists is not None:
                version_row = catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()
                existing_version = None if version_row is None else version_row[0]
            if str(existing_version) == "38":
                catalog.initialize(target_version=38)
            else:
                catalog.initialize(target_version=37)
                backup = path.parent / (
                    "20260831T180000000000Z-abcdef123456-p-v37-"
                    "0123456789abcdef.sqlite3"
                )
                catalog.backup_to(backup)
                catalog._initialize_after_protected_backup(38, backup)
        else:
            catalog.initialize(target_version=schema_version)
        for library_id in library_ids:
            source = path.parent / f"source-{library_id.casefold()}"
            source.mkdir(parents=True, exist_ok=True)
            catalog.add_library(
                library_id, f"Sanitized library {library_id}", str(source)
            )
        catalog.create_automatic_job(
            "JOB-MIGRATION",
            library_ids[0],
            "synthetic-drive",
            "/synthetic/mount",
            cassettes,
            library_ids=list(library_ids),
            force_format=True,
        )
        for sequence in range(1, total + 1):
            catalog.replace_automatic_cassette_manifest(
                "JOB-MIGRATION",
                sequence,
                [
                    (
                        library_ids[(block_number - 1) % len(library_ids)],
                        f"cassette-{sequence}/file-{block_number}.bin",
                        sequence,
                        sequence + block_number - 1,
                    )
                    for block_number in range(1, blocks_per_cassette + 1)
                ],
            )
        for sequence in range(1, completed + 1):
            tape_id = f"TAPE{sequence:02d}"
            catalog.register_tape(
                tape_id,
                f"SERIAL{sequence:02d}",
                tape_id,
                "LTFS",
                "/synthetic/mount",
                cassette_number=tape_id,
            )
            block_ids: list[str] = []
            for block_number in range(1, blocks_per_cassette + 1):
                block_id = (
                    f"BLOCK{sequence:02d}"
                    if blocks_per_cassette == 1
                    else f"BLOCK{sequence:02d}-{block_number:02d}"
                )
                block_ids.append(block_id)
                relative_path = f"cassette-{sequence}/file-{block_number}.bin"
                library_id = library_ids[(block_number - 1) % len(library_ids)]
                catalog.create_block(
                    block_id, library_id, tape_id, "archive", 1, sequence
                )
                catalog.record_file_version(
                    library_id,
                    block_id,
                    tape_id,
                    relative_path,
                    f"archive/files/{relative_path}",
                    sequence,
                    sequence + block_number - 1,
                    f"{sequence * blocks_per_cassette + block_number:064x}",
                )
                catalog.complete_block(block_id)
            catalog.update_automatic_cassette(
                "JOB-MIGRATION",
                sequence,
                "completed",
                tape_id=tape_id,
                block_id=",".join(block_ids),
                copied_files=blocks_per_cassette,
                copied_bytes=sequence * blocks_per_cassette,
            )
        if fourth_status != "pending":
            catalog.update_automatic_cassette("JOB-MIGRATION", 4, fourth_status)
        catalog.update_automatic_job(
            "JOB-MIGRATION", "waiting_media", current_sequence=completed + 1
        )
    return path


def make_public_schema_14_fixture(path: Path) -> Path:
    """Create the released foundation schema 14 without later frozen additions."""

    path = Path(path)
    with Catalog(path) as catalog:
        catalog.initialize(target_version=14)
        catalog.event("schema.fourteen.fixture", {"preserved": True})
    return path
