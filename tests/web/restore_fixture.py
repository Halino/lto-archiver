"""Synthetic restore run used by public WebUI tests."""

from __future__ import annotations

from types import SimpleNamespace


def restore_run(*, state: str = "waiting_media", conflict: bool = False):
    plan_item = SimpleNamespace(
        sequence=1,
        file_version_id=42,
        library_id="PHOTOS",
        relative_path="clips/example.mxf",
        tape_relative_path=".lto/BLOCK-1/files/clips/example.mxf",
        tape_id="TAPE-1",
        cassette_number="CASS-1",
        physical_label="B00100",
        volume_label="LTFS-001",
        block_id="BLOCK-1",
        size=1024,
        sha256="a" * 64,
    )
    conflict_record = (
        SimpleNamespace(
            id="conflict-1",
            state="recorded",
            canonical_destination="/srv/restore/PHOTOS/clips/example.mxf",
            observed_size=9,
            observed_sha256="b" * 64,
        )
        if conflict
        else None
    )
    item = SimpleNamespace(
        sequence=1,
        cassette_sequence=1,
        destination_relative_path="PHOTOS/clips/example.mxf",
        canonical_destination="/srv/restore/PHOTOS/clips/example.mxf",
        state="recovery_required" if conflict else "pending",
        bytes_copied=0,
        observed_sha256=None,
        error_code="destination_conflict" if conflict else None,
        conflict=conflict_record,
        plan_item=plan_item,
    )
    cassette = SimpleNamespace(
        sequence=1,
        plan_cassette_sequence=1,
        tape_id="TAPE-1",
        cassette_number="CASS-1",
        physical_label="B00100",
        volume_label="LTFS-001",
        state="recovery_required" if conflict else state,
        item_count=1,
        total_bytes=1024,
        restored_files=0,
        skipped_files=0,
        failed_files=0,
        copied_bytes=0,
        operation_id="operation-restore-1",
        last_error_code="destination_conflict" if conflict else None,
    )
    return SimpleNamespace(
        id="RESTORE-RUN-1",
        plan_id="RESTORE-1",
        actor="web-user-2",
        state="recovery_required" if conflict else state,
        current_cassette_sequence=1,
        total_files=1,
        total_bytes=1024,
        restored_files=0,
        skipped_files=0,
        failed_files=0,
        copied_bytes=0,
        last_error_code="destination_conflict" if conflict else None,
        cassettes=(cassette,),
        items=(item,),
    )
