"""Manual, disabled-by-default entry point for physical LTFS qualification."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import secrets
import sqlite3
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import TextIO

from ltobackup.broker.client import (
    BrokerUnavailable,
    LtfsQualificationApi,
    UnixBrokeredCgroupScopeApi,
)
from ltobackup.catalog import SCHEMA_VERSION, Catalog
from ltobackup.daemon.models import HardwareTargetBinding, media_identity_sha256
from ltobackup.errors import CatalogError
from ltobackup.linux_settings import load_linux_settings
from ltobackup.operational_log import (
    JournalOperationalEventSink,
    OperationalEvent,
    OperationalSeverity,
    OperationalSource,
)
from ltobackup.tape.command_supervisor import BrokeredCgroupScopeToken
from ltobackup.tape.linux_ltfs import SysfsDeviceIdentityProvider
from ltobackup.tape.models import ExpectedMedia, MediaIdentity

from .broker_models import (
    BrokerQualificationInspection,
    BrokerQualificationInspectionRequest,
    BrokerQualificationRequest,
    qualification_request_operation_token,
)
from .plan import (
    SUPPORTED_QUALIFICATION_OPERATIONS,
    QualificationOperation,
    QualificationPlan,
    QualificationRefused,
)

_MAX_PLAN_BYTES = 64 * 1024
_SETTINGS_PATH = Path("/etc/lto-archiver/config.toml")
_LTFS_DEVICE_CONFIG = Path("/etc/lto-ltfs/device.json")
_ARTIFACT_ATTESTATION = Path("/etc/lto-archiver/qualification-artifacts.json")
_LTFS_INFO = Path("/usr/bin/ltfs-info")
_BROKER_SOCKET = Path("/run/lto-archiver-broker/control.sock")
_BROKER_CAPABILITY = Path(
    "/run/credentials/lto-archiver-ltfs-qualification.service/broker-capability"
)
_QUALIFICATION_CREDENTIAL = Path(
    "/run/credentials/lto-archiver-ltfs-qualification.service/qualification-credential"
)
_OPERATION_TOKEN = Path(
    "/run/credentials/lto-archiver-ltfs-qualification.service/operation-token"
)
_ACTIVE_PLAN = Path("/var/lib/lto-archiver/qualification/active-plan.json")
_ACTIVE_CATALOG = Path("/var/lib/lto-archiver/catalog.db")
_PROBE_SNAPSHOT_ROOT = Path("/run/lto-archiver/qualification")
_MAX_PROBE_CATALOG_BYTES = 1 << 30
_MAX_PROBE_WAL_BYTES = 1 << 30
_MAX_PROBE_SHM_BYTES = 64 << 20
_EXECUTION_ORDER = (
    QualificationOperation.READ_ONLY,
    QualificationOperation.FORMAT,
    QualificationOperation.ADDITIVE_WRITE,
    QualificationOperation.OVERWRITE,
    QualificationOperation.REPAIR,
    QualificationOperation.WIPE,
    QualificationOperation.UNLOAD,
    QualificationOperation.LOAD,
    QualificationOperation.EJECT,
)
_ADMIN_GROUP = "lto-admin"
_OPERATION_CHOICES = tuple(operation.value for operation in _EXECUTION_ORDER)


def _closed_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = value
    return result


def _effective_ids() -> tuple[int, int]:
    return os.geteuid(), os.getegid()


def _read_plan(path: Path) -> QualificationPlan:
    if not path.is_absolute():
        raise QualificationRefused("qualification plan path is invalid")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            status = os.fstat(descriptor)
            if (
                not stat.S_ISREG(status.st_mode)
                or status.st_nlink != 1
                or status.st_uid != os.geteuid()
                or status.st_gid != os.getegid()
                or stat.S_IMODE(status.st_mode) != 0o600
                or not 0 < status.st_size <= _MAX_PLAN_BYTES
            ):
                raise QualificationRefused("qualification plan file is invalid")
            payload = os.read(descriptor, _MAX_PLAN_BYTES + 1)
            if len(payload) != status.st_size:
                raise QualificationRefused("qualification plan file changed")
            after = os.fstat(descriptor)
            if _file_snapshot(after) != _file_snapshot(status):
                raise QualificationRefused("qualification plan file changed")
        finally:
            os.close(descriptor)
    except OSError:
        raise QualificationRefused("qualification plan is unavailable") from None
    return QualificationPlan.from_bytes(payload)


def _read_root_credential(path: Path) -> bytes:
    if _effective_ids() != (0, 0) or not path.is_absolute():
        raise QualificationRefused("qualification credential is unavailable")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != 0
            or status.st_gid != 0
            or stat.S_IMODE(status.st_mode) != 0o400
            or status.st_nlink != 1
            or status.st_size != 32
        ):
            raise QualificationRefused("qualification credential is unavailable")
        value = os.read(descriptor, 33)
        after = os.fstat(descriptor)
        if (
            len(value) != 32
            or os.read(descriptor, 1)
            or _file_snapshot(after) != _file_snapshot(status)
        ):
            raise QualificationRefused("qualification credential is unavailable")
        return value
    except OSError:
        raise QualificationRefused("qualification credential is unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_operation_token(path: Path) -> str:
    if _effective_ids() != (0, 0) or not path.is_absolute():
        raise QualificationRefused("qualification operation token is unavailable")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != 0
            or status.st_gid != 0
            or stat.S_IMODE(status.st_mode) != 0o400
            or status.st_nlink != 1
            or status.st_size != 64
        ):
            raise QualificationRefused("qualification operation token is unavailable")
        raw = os.read(descriptor, 65)
        value = raw.decode("ascii")
        if len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise QualificationRefused("qualification operation token is unavailable")
        return value
    except (OSError, UnicodeDecodeError):
        raise QualificationRefused(
            "qualification operation token is unavailable"
        ) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _file_snapshot(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_nlink,
        status.st_uid,
        status.st_gid,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _private_probe_file_snapshot(status: os.stat_result) -> tuple[int, ...]:
    return _file_snapshot(status)[:-1]


def _connect_broker(credential_path: Path = _BROKER_CAPABILITY) -> LtfsQualificationApi:
    capability = _read_root_credential(credential_path)
    return UnixBrokeredCgroupScopeApi(
        _BROKER_SOCKET,
        BrokeredCgroupScopeToken(capability),
        timeout=30.0,
        ltfs_lifecycle_timeout=86_400.0,
    )


class QualificationEnvironmentEvidence:
    __slots__ = (
        "drive_serial",
        "drive_wwid",
        "expected_media_scope_sha256",
        "generation",
        "linux_tree_sha256",
        "ltfs_rpm_sha256",
        "ltfs_tree_sha256",
        "observed_media_identity_sha256",
        "physical_label",
        "scsi_device_identity_sha256",
        "tape_device_identity_sha256",
        "tape_serial",
        "volume_uuid",
    )

    def __init__(
        self,
        *,
        physical_label: str,
        tape_serial: str,
        drive_serial: str,
        drive_wwid: str,
        linux_tree_sha256: str,
        ltfs_tree_sha256: str,
        ltfs_rpm_sha256: str,
        tape_device_identity_sha256: str,
        scsi_device_identity_sha256: str,
        expected_media_scope_sha256: str,
        observed_media_identity_sha256: str,
        volume_uuid: str | None,
        generation: int | None,
    ) -> None:
        self.physical_label = physical_label
        self.tape_serial = tape_serial
        self.drive_serial = drive_serial
        self.drive_wwid = drive_wwid
        self.linux_tree_sha256 = linux_tree_sha256
        self.ltfs_tree_sha256 = ltfs_tree_sha256
        self.ltfs_rpm_sha256 = ltfs_rpm_sha256
        self.tape_device_identity_sha256 = tape_device_identity_sha256
        self.scsi_device_identity_sha256 = scsi_device_identity_sha256
        self.expected_media_scope_sha256 = expected_media_scope_sha256
        self.observed_media_identity_sha256 = observed_media_identity_sha256
        self.volume_uuid = volume_uuid
        self.generation = generation


def _prepare_environment(
    plan: QualificationPlan,
    operation: QualificationOperation,
    catalog_path: Path | None = None,
) -> QualificationEnvironmentEvidence:
    settings = load_linux_settings(_SETTINGS_PATH)
    device_config = _read_closed_json(
        _LTFS_DEVICE_CONFIG,
        frozenset({"nst_path", "sg_path", "serial", "wwid"}),
        expected_mode=0o640,
        expected_group=_ADMIN_GROUP,
    )
    artifacts = _read_closed_json(
        _ARTIFACT_ATTESTATION,
        frozenset(
            {
                "schema",
                "linux_tree_sha256",
                "ltfs_tree_sha256",
                "ltfs_rpm_sha256",
                "tool_sha256",
            }
        ),
        expected_mode=0o400,
        require_canonical=True,
    )
    if (
        artifacts["schema"] != 2
        or device_config["nst_path"] != str(settings.tape_device_path)
        or device_config["sg_path"] != str(settings.scsi_device_path)
        or device_config["serial"] != plan.drive_serial
        or device_config["wwid"] != plan.drive_wwid
    ):
        raise QualificationRefused("qualification device or artifact authority changed")
    for key in ("linux_tree_sha256", "ltfs_tree_sha256", "ltfs_rpm_sha256"):
        value = artifacts[key]
        if (
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise QualificationRefused("qualification artifact authority is invalid")
    tool_sha256 = artifacts["tool_sha256"]
    expected_tools = frozenset(
        {"ltfs", "mkltfs", "ltfsck", "ltfs-info", "fusermount", "mt"}
    )
    if (
        type(tool_sha256) is not dict
        or frozenset(tool_sha256) != expected_tools
        or any(
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in tool_sha256.values()
        )
    ):
        raise QualificationRefused("qualification artifact authority is invalid")

    if operation is QualificationOperation.LOAD:
        if not isinstance(catalog_path, Path) or not catalog_path.is_absolute():
            raise QualificationRefused("qualification load evidence is unavailable")
        with Catalog(catalog_path) as catalog:
            row = catalog.connection.execute(
                "SELECT d.request_sha256,d.before_volume_uuid,d.before_generation,"
                "t.terminal_receipt_sha256,t.child_exit_code "
                "FROM ltfs_qualification_stages AS d "
                "JOIN ltfs_qualification_stages AS t "
                "ON t.run_id=d.run_id AND t.ordinal=d.ordinal+1 "
                "AND t.operation=d.operation "
                "AND t.request_sha256=d.request_sha256 "
                "WHERE d.run_id=? AND d.operation='unload' "
                "AND d.verdict='dispatch_started' AND d.dispatched=1 "
                "AND t.verdict='pass' AND t.dispatched=1 "
                "AND t.terminal_receipt_sha256 IS NOT NULL "
                "AND t.child_exit_code=0 ORDER BY d.ordinal DESC LIMIT 1",
                (plan.run_id,),
            ).fetchone()
        if (
            row is None
            or type(row["request_sha256"]) is not str
            or type(row["before_volume_uuid"]) is not str
            or type(row["before_generation"]) is not int
            or type(row["terminal_receipt_sha256"]) is not str
            or type(row["child_exit_code"]) is not int
        ):
            raise QualificationRefused("qualification load evidence is unavailable")
        inspection_request = BrokerQualificationInspectionRequest(
            run_id=plan.run_id,
            stage_ordinal=_EXECUTION_ORDER.index(QualificationOperation.UNLOAD) + 1,
            challenge=secrets.token_bytes(32),
        )
        inspection = _connect_broker().inspect_ltfs_qualification_stage(
            inspection_request
        )
        snapshot = _validate_terminal_inspection(
            plan,
            QualificationOperation.UNLOAD,
            row["request_sha256"],
            inspection_request,
            inspection,
        )
        dispatch = inspection.dispatch
        if (
            dispatch is None
            or dispatch.terminal_receipt_sha256 != row["terminal_receipt_sha256"]
            or dispatch.child_exit_code != row["child_exit_code"]
            or snapshot["expected_physical_label"] != plan.physical_label
            or snapshot["expected_tape_serial"] != plan.tape_serial
            or snapshot["expected_drive_serial"] != plan.drive_serial
            or snapshot["expected_drive_wwid"] != plan.drive_wwid
            or snapshot["expected_volume_uuid"] != row["before_volume_uuid"]
            or snapshot["expected_generation"] != row["before_generation"]
        ):
            raise QualificationRefused("qualification load evidence is unavailable")
        provider = SysfsDeviceIdentityProvider()
        tape = provider.resolve(settings.tape_device_path)
        scsi = provider.resolve(settings.scsi_device_path)
        if (
            tape.scsi_unit_identity != scsi.scsi_unit_identity
            or tape.serial_token != plan.drive_serial
            or scsi.serial_token != plan.drive_serial
        ):
            raise QualificationRefused("qualification device tuple mismatch")
        expected = ExpectedMedia(
            f"qualification.{operation.value}",
            plan.job_id,
            plan.cassette_sequence,
            plan.physical_label,
            None,
            row["before_volume_uuid"],
        )
        binding = HardwareTargetBinding.from_verified_inputs(
            settings.mount_path,
            tape.canonical_json(),
            scsi.canonical_json(),
            expected.target_scope(),
        )
        return QualificationEnvironmentEvidence(
            physical_label=plan.physical_label,
            tape_serial=plan.tape_serial,
            drive_serial=plan.drive_serial,
            drive_wwid=plan.drive_wwid,
            linux_tree_sha256=artifacts["linux_tree_sha256"],
            ltfs_tree_sha256=artifacts["ltfs_tree_sha256"],
            ltfs_rpm_sha256=artifacts["ltfs_rpm_sha256"],
            tape_device_identity_sha256=binding.tape_device_identity_sha256,
            scsi_device_identity_sha256=binding.scsi_device_identity_sha256,
            expected_media_scope_sha256=binding.expected_media_scope_sha256,
            observed_media_identity_sha256=snapshot["observed_media_identity_sha256"],
            volume_uuid=row["before_volume_uuid"],
            generation=row["before_generation"],
        )

    payload = _run_ltfs_info(
        tool_sha256["ltfs-info"],
        mode=(
            "pre-format" if operation is QualificationOperation.FORMAT else "unmounted"
        ),
    )
    required = frozenset(
        {
            "schema",
            "media_state",
            "tape_by_id",
            "scsi_by_id",
            "drive_serial",
            "mam_barcode",
            "mam_volume_serial",
            "ltfs_volume_label",
            "ltfs_volume_uuid",
            "index_generation",
        }
    )
    if frozenset(payload) != required or payload["schema"] != 2:
        raise QualificationRefused("qualification media label identity mismatch")
    if (
        payload["tape_by_id"] != str(settings.tape_device_path)
        or payload["scsi_by_id"] != str(settings.scsi_device_path)
        or payload["drive_serial"] != plan.drive_serial
        or type(payload["mam_volume_serial"]) is not str
        or not payload["mam_volume_serial"]
        or (
            plan.expected_mam_medium_serial is not None
            and payload["mam_volume_serial"] != plan.expected_mam_medium_serial
        )
    ):
        raise QualificationRefused("qualification media label identity mismatch")
    volume_uuid = payload["ltfs_volume_uuid"]
    generation = payload["index_generation"]
    if payload["media_state"] == "ltfs":
        if (
            payload["mam_barcode"] != plan.physical_label
            or payload["ltfs_volume_label"] != plan.physical_label
            or not _canonical_ltfs_uuid(volume_uuid)
            or type(generation) is not int
            or generation <= 0
        ):
            raise QualificationRefused("qualification LTFS media state is incomplete")
    elif payload["media_state"] == "unidentified":
        if (
            operation is not QualificationOperation.FORMAT
            or (
                payload["mam_barcode"] is not None
                and payload["mam_barcode"] != plan.physical_label
            )
            or payload["ltfs_volume_label"] is not None
            or volume_uuid is not None
            or generation is not None
        ):
            raise QualificationRefused("qualification LTFS media state is incomplete")
    else:
        raise QualificationRefused("qualification LTFS media state is incomplete")

    provider = SysfsDeviceIdentityProvider()
    tape = provider.resolve(settings.tape_device_path)
    scsi = provider.resolve(settings.scsi_device_path)
    if (
        tape.scsi_unit_identity != scsi.scsi_unit_identity
        or tape.serial_token != plan.drive_serial
        or scsi.serial_token != plan.drive_serial
    ):
        raise QualificationRefused("qualification device tuple mismatch")
    expected = ExpectedMedia(
        f"qualification.{operation.value}",
        plan.job_id,
        plan.cassette_sequence,
        plan.physical_label,
        None,
        volume_uuid,
    )
    binding = HardwareTargetBinding.from_verified_inputs(
        settings.mount_path,
        tape.canonical_json(),
        scsi.canonical_json(),
        expected.target_scope(),
    )
    observed = MediaIdentity(
        drive_serial=payload["drive_serial"],
        mam_barcode=payload["mam_barcode"],
        mam_volume_serial=payload["mam_volume_serial"],
        ltfs_volume_label=payload["ltfs_volume_label"],
        ltfs_volume_uuid=volume_uuid,
    )
    return QualificationEnvironmentEvidence(
        physical_label=plan.physical_label,
        tape_serial=plan.tape_serial,
        drive_serial=plan.drive_serial,
        drive_wwid=plan.drive_wwid,
        linux_tree_sha256=artifacts["linux_tree_sha256"],
        ltfs_tree_sha256=artifacts["ltfs_tree_sha256"],
        ltfs_rpm_sha256=artifacts["ltfs_rpm_sha256"],
        tape_device_identity_sha256=binding.tape_device_identity_sha256,
        scsi_device_identity_sha256=binding.scsi_device_identity_sha256,
        expected_media_scope_sha256=binding.expected_media_scope_sha256,
        observed_media_identity_sha256=media_identity_sha256(
            observed.canonical_fields()
        ),
        volume_uuid=volume_uuid,
        generation=generation,
    )


def _read_closed_json(
    path: Path,
    keys: frozenset[str],
    *,
    expected_mode: int | None = None,
    expected_group: str | None = None,
    require_canonical: bool = False,
) -> dict[str, object]:
    if not path.is_absolute():
        raise QualificationRefused("qualification authority path is invalid")
    descriptor = -1
    try:
        expected_gid = (
            0 if expected_group is None else grp.getgrnam(expected_group).gr_gid
        )
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != 0
            or status.st_gid != expected_gid
            or status.st_nlink != 1
            or (
                expected_mode is not None
                and stat.S_IMODE(status.st_mode) != expected_mode
            )
            or not 0 < status.st_size <= 16 * 1024
        ):
            raise QualificationRefused("qualification authority file is invalid")
        raw = os.read(descriptor, 16 * 1024 + 1)
        after = os.fstat(descriptor)
        if (
            len(raw) != status.st_size
            or os.read(descriptor, 1)
            or _file_snapshot(after) != _file_snapshot(status)
        ):
            raise QualificationRefused("qualification authority file changed")
        value = json.loads(raw, object_pairs_hook=_closed_object_pairs)
    except (KeyError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise QualificationRefused("qualification authority is unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        type(value) is not dict
        or frozenset(value) != keys
        or (
            require_canonical
            and raw
            != (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "ascii"
            )
        )
    ):
        raise QualificationRefused("qualification authority schema is invalid")
    return value


def _run_ltfs_info(expected_sha256: str, *, mode: str) -> dict[str, object]:
    if (
        type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
        or mode not in {"unmounted", "pre-format"}
    ):
        raise QualificationRefused("ltfs-info tool identity is invalid")
    descriptor = -1
    try:
        descriptor = os.open(_LTFS_INFO, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != 0
            or status.st_gid != 0
            or status.st_nlink != 1
            or not status.st_mode & stat.S_IXUSR
            or status.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 0 < status.st_size <= 64 * 1024 * 1024
        ):
            raise QualificationRefused("ltfs-info tool identity is invalid")
        snapshot = (
            status.st_dev,
            status.st_ino,
            status.st_mode,
            status.st_nlink,
            status.st_uid,
            status.st_gid,
            status.st_size,
            status.st_mtime_ns,
        )
        digest = hashlib.sha256()
        remaining = status.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise QualificationRefused("ltfs-info tool identity changed")
            digest.update(chunk)
            remaining -= len(chunk)
        if digest.hexdigest() != expected_sha256 or os.read(descriptor, 1):
            raise QualificationRefused("ltfs-info tool identity changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
        ) != snapshot:
            raise QualificationRefused("ltfs-info tool identity changed")
        completed = subprocess.run(
            (f"/proc/self/fd/{descriptor}", "--json", "--mode", mode),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=30.0,
            check=False,
            pass_fds=(descriptor,),
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/usr/sbin"},
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise QualificationRefused("ltfs-info probe is unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 4096:
        raise QualificationRefused("ltfs-info probe failed")
    try:
        payload = json.loads(completed.stdout, object_pairs_hook=_closed_object_pairs)
    except (json.JSONDecodeError, TypeError, ValueError):
        raise QualificationRefused("ltfs-info evidence is invalid") from None
    if type(payload) is not dict:
        raise QualificationRefused("ltfs-info evidence is invalid")
    return payload


def _run_ltfs_terminal_state(
    expected_sha256: str, operation: QualificationOperation
) -> None:
    expected_returncode = {
        QualificationOperation.WIPE: 5,
        QualificationOperation.UNLOAD: 3,
        QualificationOperation.EJECT: 3,
    }.get(operation)
    if (
        expected_returncode is None
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise QualificationRefused("ltfs-info terminal oracle is invalid")
    descriptor = -1
    try:
        descriptor = os.open(_LTFS_INFO, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != 0
            or status.st_gid != 0
            or status.st_nlink != 1
            or not status.st_mode & stat.S_IXUSR
            or status.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 0 < status.st_size <= 64 * 1024 * 1024
        ):
            raise QualificationRefused("ltfs-info tool identity is invalid")
        snapshot = _file_snapshot(status)
        digest = hashlib.sha256()
        remaining = status.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise QualificationRefused("ltfs-info tool identity changed")
            digest.update(chunk)
            remaining -= len(chunk)
        if digest.hexdigest() != expected_sha256 or os.read(descriptor, 1):
            raise QualificationRefused("ltfs-info tool identity changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        if _file_snapshot(os.fstat(descriptor)) != snapshot:
            raise QualificationRefused("ltfs-info tool identity changed")
        completed = subprocess.run(
            (f"/proc/self/fd/{descriptor}", "--json", "--mode", "unmounted"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=30.0,
            check=False,
            pass_fds=(descriptor,),
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/usr/sbin"},
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise QualificationRefused("ltfs-info terminal probe is unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if completed.returncode != expected_returncode or completed.stdout != "":
        raise QualificationRefused("ltfs-info terminal media state is ambiguous")


def _prepare_reconciliation_environment(
    plan: QualificationPlan,
    operation: QualificationOperation,
    snapshot: Mapping[str, object],
    catalog_path: Path,
) -> QualificationEnvironmentEvidence:
    identity_operations = {
        QualificationOperation.READ_ONLY,
        QualificationOperation.FORMAT,
        QualificationOperation.ADDITIVE_WRITE,
        QualificationOperation.OVERWRITE,
        QualificationOperation.REPAIR,
        QualificationOperation.LOAD,
    }
    if operation in identity_operations:
        return _prepare_environment(
            plan, QualificationOperation.READ_ONLY, catalog_path
        )

    settings = load_linux_settings(_SETTINGS_PATH)
    device_config = _read_closed_json(
        _LTFS_DEVICE_CONFIG,
        frozenset({"nst_path", "sg_path", "serial", "wwid"}),
        expected_mode=0o640,
        expected_group=_ADMIN_GROUP,
    )
    artifacts = _read_closed_json(
        _ARTIFACT_ATTESTATION,
        frozenset(
            {
                "schema",
                "linux_tree_sha256",
                "ltfs_tree_sha256",
                "ltfs_rpm_sha256",
                "tool_sha256",
            }
        ),
        expected_mode=0o400,
        require_canonical=True,
    )
    tool_sha256 = artifacts.get("tool_sha256")
    expected_tools = frozenset(
        {"ltfs", "mkltfs", "ltfsck", "ltfs-info", "fusermount", "mt"}
    )
    if (
        artifacts.get("schema") != 2
        or artifacts.get("linux_tree_sha256") != plan.linux_tree_sha256
        or artifacts.get("ltfs_tree_sha256") != plan.ltfs_tree_sha256
        or artifacts.get("ltfs_rpm_sha256") != plan.ltfs_rpm_sha256
        or type(tool_sha256) is not dict
        or frozenset(tool_sha256) != expected_tools
        or any(
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in tool_sha256.values()
        )
        or device_config.get("nst_path") != str(settings.tape_device_path)
        or device_config.get("sg_path") != str(settings.scsi_device_path)
        or device_config.get("serial") != plan.drive_serial
        or device_config.get("wwid") != plan.drive_wwid
    ):
        raise QualificationRefused("qualification device or artifact authority changed")
    _run_ltfs_terminal_state(tool_sha256["ltfs-info"], operation)
    provider = SysfsDeviceIdentityProvider()
    tape = provider.resolve(settings.tape_device_path)
    scsi = provider.resolve(settings.scsi_device_path)
    if (
        tape.scsi_unit_identity != scsi.scsi_unit_identity
        or tape.serial_token != plan.drive_serial
        or scsi.serial_token != plan.drive_serial
    ):
        raise QualificationRefused("qualification device tuple mismatch")
    expected = ExpectedMedia(
        f"qualification.{operation.value}",
        plan.job_id,
        plan.cassette_sequence,
        plan.physical_label,
        None,
        snapshot.get("expected_volume_uuid"),
    )
    binding = HardwareTargetBinding.from_verified_inputs(
        settings.mount_path,
        tape.canonical_json(),
        scsi.canonical_json(),
        expected.target_scope(),
    )
    return QualificationEnvironmentEvidence(
        physical_label=plan.physical_label,
        tape_serial=plan.tape_serial,
        drive_serial=plan.drive_serial,
        drive_wwid=plan.drive_wwid,
        linux_tree_sha256=plan.linux_tree_sha256,
        ltfs_tree_sha256=plan.ltfs_tree_sha256,
        ltfs_rpm_sha256=plan.ltfs_rpm_sha256,
        tape_device_identity_sha256=binding.tape_device_identity_sha256,
        scsi_device_identity_sha256=binding.scsi_device_identity_sha256,
        expected_media_scope_sha256=binding.expected_media_scope_sha256,
        observed_media_identity_sha256=snapshot["observed_media_identity_sha256"],
        volume_uuid=None,
        generation=None,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lto-archiver-qualify-ltfs")
    subparsers = parser.add_subparsers(dest="action", required=True)

    def add_identity_arguments(command: argparse.ArgumentParser) -> None:
        command.add_argument("--catalog", type=Path, required=True)
        command.add_argument("--job-id", required=True)
        command.add_argument("--cassette-sequence", type=int, required=True)
        command.add_argument("--expected-label", required=True)
        command.add_argument("--expected-mam-medium-serial")
        command.add_argument("--drive-serial", required=True)
        command.add_argument("--drive-wwid", required=True)
        command.add_argument("--linux-tree-sha256", required=True)
        command.add_argument("--ltfs-tree-sha256", required=True)
        command.add_argument("--ltfs-rpm-sha256", required=True)

    probe = subparsers.add_parser("probe")
    add_identity_arguments(probe)
    plan = subparsers.add_parser("plan")
    add_identity_arguments(plan)
    plan.add_argument(
        "--operation",
        action="append",
        choices=_OPERATION_CHOICES,
        required=True,
    )
    plan.add_argument("--expires-seconds", type=int, default=3600)

    authorize = subparsers.add_parser("authorize")
    authorize.add_argument("--plan", type=Path, required=True)
    authorize.add_argument(
        "--operation",
        choices=_OPERATION_CHOICES,
        required=True,
    )
    authorize.add_argument("--credential", type=Path, required=True)
    execute = subparsers.add_parser("execute-stage")
    execute.add_argument("--catalog", type=Path, required=True)
    execute.add_argument("--plan", type=Path, required=True)
    execute.add_argument(
        "--operation",
        choices=_OPERATION_CHOICES,
        required=True,
    )
    execute.add_argument("--token", required=True)
    execute.add_argument("--credential", type=Path, required=True)
    reconcile = subparsers.add_parser("reconcile-stage")
    reconcile.add_argument("--catalog", type=Path, required=True)
    reconcile.add_argument("--plan", type=Path, required=True)
    reconcile.add_argument("--credential", type=Path, required=True)
    subparsers.add_parser("execute-approved-stage")
    return parser


def _probe_media(
    arguments: argparse.Namespace,
    output: TextIO,
    *,
    now_ns: int,
    run_id: str,
) -> int:
    if _effective_ids() != (0, 0):
        raise QualificationRefused("qualification probe requires root")
    if arguments.catalog != _ACTIVE_CATALOG:
        raise QualificationRefused("qualification probe catalog is invalid")
    cassette = _read_probe_catalog_cassette(
        arguments.catalog,
        job_id=arguments.job_id,
        cassette_sequence=arguments.cassette_sequence,
    )
    plan = QualificationPlan.from_catalog(
        cassette,
        run_id=run_id,
        expected_physical_label=arguments.expected_label,
        expected_mam_medium_serial=arguments.expected_mam_medium_serial,
        drive_serial=arguments.drive_serial,
        drive_wwid=arguments.drive_wwid,
        linux_tree_sha256=arguments.linux_tree_sha256,
        ltfs_tree_sha256=arguments.ltfs_tree_sha256,
        ltfs_rpm_sha256=arguments.ltfs_rpm_sha256,
        issued_at_ns=now_ns,
        expires_at_ns=now_ns + 3_600_000_000_000,
        operations=(QualificationOperation.FORMAT,),
    )
    evidence = _prepare_environment(
        plan, QualificationOperation.FORMAT, arguments.catalog
    )
    if not _evidence_matches_plan(evidence, plan):
        raise QualificationRefused("qualification probe identity changed")
    if evidence.volume_uuid is None and evidence.generation is None:
        media_state = "unidentified"
        initial_operation = QualificationOperation.FORMAT.value
    elif (
        type(evidence.volume_uuid) is str
        and type(evidence.generation) is int
        and evidence.generation > 0
    ):
        media_state = "ltfs"
        initial_operation = QualificationOperation.READ_ONLY.value
    else:
        raise QualificationRefused("qualification LTFS media state is incomplete")
    output.write(
        json.dumps(
            {
                "initial_operation": initial_operation,
                "media_state": media_state,
                "schema": 2,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    return 0


def _probe_fd_sha256(descriptor: int, expected_size: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    remaining = expected_size
    digest = hashlib.sha256()
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            raise OSError("short probe catalog read")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise OSError("long probe catalog read")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _probe_wal_is_well_formed(descriptor: int, size: int) -> bool:
    if size == 0:
        return True
    if size < 32:
        return False
    header = os.pread(descriptor, 32, 0)
    if len(header) != 32 or int.from_bytes(header[:4], "big") not in {
        0x377F0682,
        0x377F0683,
    }:
        return False
    page_size = int.from_bytes(header[8:12], "big")
    if page_size == 1:
        page_size = 65_536
    return not (
        page_size < 512
        or page_size > 65_536
        or page_size & (page_size - 1)
        or (size - 32) % (page_size + 24)
    )


def _open_probe_catalog_file(
    parent_fd: int,
    name: str,
    *,
    expected_uid_gid: tuple[int, int],
    maximum_size: int,
    empty_allowed: bool,
    required: bool,
) -> tuple[int, tuple[int, ...], str] | None:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        if required:
            raise
        return None
    try:
        details = os.fstat(descriptor)
        path_details = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or (details.st_uid, details.st_gid) != expected_uid_gid
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_size > maximum_size
            or (not empty_allowed and details.st_size == 0)
            or _file_snapshot(path_details) != _file_snapshot(details)
        ):
            raise QualificationRefused("qualification probe catalog is invalid")
        digest = _probe_fd_sha256(descriptor, details.st_size)
        return descriptor, _file_snapshot(details), digest
    except Exception:
        os.close(descriptor)
        raise


def _probe_catalog_family(parent_fd: int, basename: str) -> set[str]:
    prefix = f"{basename}-"
    return {name for name in os.listdir(parent_fd) if name.startswith(prefix)}


def _probe_catalog_source_is_unchanged(
    parent_fd: int,
    basename: str,
    authorities: Mapping[str, tuple[int, tuple[int, ...], str]],
    expected_family: set[str],
) -> bool:
    try:
        if _probe_catalog_family(parent_fd, basename) != expected_family:
            return False
        for name, (descriptor, before, digest) in authorities.items():
            if (
                _file_snapshot(os.fstat(descriptor)) != before
                or _file_snapshot(
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                )
                != before
                or _probe_fd_sha256(descriptor, before[6]) != digest
            ):
                return False
        return True
    except OSError:
        return False


@contextmanager
def _probe_snapshot_workspace() -> Iterator[int]:
    root_fd = -1
    workspace_fd = -1
    workspace_name: str | None = None
    cleanup_error = False
    try:
        root_fd = os.open(
            _PROBE_SNAPSHOT_ROOT,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        root_details = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_details.st_mode)
            or root_details.st_nlink < 2
            or (root_details.st_uid, root_details.st_gid)
            != (os.geteuid(), os.getegid())
            or stat.S_IMODE(root_details.st_mode) != 0o700
        ):
            raise QualificationRefused(
                "qualification probe snapshot root is invalid"
            )
        for _ in range(16):
            candidate = f".catalog-probe-{secrets.token_hex(16)}"
            try:
                os.mkdir(candidate, mode=0o700, dir_fd=root_fd)
            except FileExistsError:
                continue
            workspace_name = candidate
            break
        if workspace_name is None:
            raise QualificationRefused(
                "qualification probe snapshot is unavailable"
            )
        workspace_fd = os.open(
            workspace_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
        workspace_details = os.fstat(workspace_fd)
        if (
            not stat.S_ISDIR(workspace_details.st_mode)
            or workspace_details.st_nlink != 2
            or (workspace_details.st_uid, workspace_details.st_gid)
            != (os.geteuid(), os.getegid())
            or stat.S_IMODE(workspace_details.st_mode) != 0o700
        ):
            raise QualificationRefused("qualification probe snapshot is invalid")
        yield workspace_fd
    finally:
        if workspace_fd >= 0:
            try:
                for name in os.listdir(workspace_fd):
                    os.unlink(name, dir_fd=workspace_fd)
            except OSError:
                cleanup_error = True
            os.close(workspace_fd)
        if root_fd >= 0 and workspace_name is not None:
            try:
                os.rmdir(workspace_name, dir_fd=root_fd)
            except OSError:
                cleanup_error = True
        if root_fd >= 0:
            os.close(root_fd)
        if cleanup_error:
            raise QualificationRefused(
                "qualification probe snapshot cleanup failed"
            ) from None


def _copy_probe_catalog_file(
    source: tuple[int, tuple[int, ...], str],
    destination_fd: int,
    name: str,
) -> tuple[int, tuple[int, ...], str]:
    source_fd, source_snapshot, source_digest = source
    target_fd = os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=destination_fd,
    )
    try:
        os.lseek(source_fd, 0, os.SEEK_SET)
        remaining = source_snapshot[6]
        while remaining:
            chunk = os.read(source_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise OSError("short probe catalog copy")
            view = memoryview(chunk)
            while view:
                written = os.write(target_fd, view)
                if written <= 0:
                    raise OSError("short probe catalog write")
                view = view[written:]
            remaining -= len(chunk)
        if os.read(source_fd, 1):
            raise OSError("long probe catalog copy")
        os.lseek(source_fd, 0, os.SEEK_SET)
        os.fsync(target_fd)
        target_details = os.fstat(target_fd)
        path_details = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
        target_digest = _probe_fd_sha256(target_fd, target_details.st_size)
        if (
            not stat.S_ISREG(target_details.st_mode)
            or target_details.st_nlink != 1
            or (target_details.st_uid, target_details.st_gid)
            != (os.geteuid(), os.getegid())
            or stat.S_IMODE(target_details.st_mode) != 0o600
            or target_details.st_size != source_snapshot[6]
            or target_digest != source_digest
            or _file_snapshot(path_details) != _file_snapshot(target_details)
        ):
            raise QualificationRefused("qualification probe snapshot is invalid")
        return target_fd, _file_snapshot(target_details), target_digest
    except Exception:
        os.close(target_fd)
        raise


def _read_probe_catalog_cassette(
    path: Path,
    *,
    job_id: str,
    cassette_sequence: int,
) -> Mapping[str, object]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise QualificationRefused("qualification probe catalog is invalid")
    parent_fd = -1
    source_files: dict[str, tuple[int, tuple[int, ...], str]] = {}
    snapshot_files: dict[str, tuple[int, tuple[int, ...], str]] = {}
    connection: sqlite3.Connection | None = None
    try:
        if path.parent.resolve(strict=True) != path.parent or "/" in path.name:
            raise QualificationRefused("qualification probe catalog is invalid")
        account = pwd.getpwnam("lto-archiver")
        expected_uid_gid = (account.pw_uid, account.pw_gid)
        parent_fd = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        parent_status = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_status.st_mode)
            or (parent_status.st_uid, parent_status.st_gid) != expected_uid_gid
            or stat.S_IMODE(parent_status.st_mode) != 0o750
        ):
            raise QualificationRefused("qualification probe catalog is invalid")
        expected_family = _probe_catalog_family(parent_fd, path.name)
        allowed_family = {f"{path.name}-wal", f"{path.name}-shm"}
        if not expected_family <= allowed_family:
            raise QualificationRefused("qualification probe catalog is invalid")
        main = _open_probe_catalog_file(
            parent_fd,
            path.name,
            expected_uid_gid=expected_uid_gid,
            maximum_size=_MAX_PROBE_CATALOG_BYTES,
            empty_allowed=False,
            required=True,
        )
        assert main is not None
        source_files[path.name] = main
        for suffix, maximum_size in (
            ("-wal", _MAX_PROBE_WAL_BYTES),
            ("-shm", _MAX_PROBE_SHM_BYTES),
        ):
            name = f"{path.name}{suffix}"
            authority = _open_probe_catalog_file(
                parent_fd,
                name,
                expected_uid_gid=expected_uid_gid,
                maximum_size=maximum_size,
                empty_allowed=True,
                required=False,
            )
            if authority is not None:
                source_files[name] = authority
        wal = source_files.get(f"{path.name}-wal")
        if wal is not None and not _probe_wal_is_well_formed(wal[0], wal[1][6]):
            raise QualificationRefused("qualification probe catalog is invalid")
        if not _probe_catalog_source_is_unchanged(
            parent_fd, path.name, source_files, expected_family
        ):
            raise QualificationRefused("qualification probe catalog changed")

        with _probe_snapshot_workspace() as workspace_fd:
            snapshot_files[path.name] = _copy_probe_catalog_file(
                source_files[path.name], workspace_fd, path.name
            )
            if wal is not None:
                wal_name = f"{path.name}-wal"
                snapshot_files[wal_name] = _copy_probe_catalog_file(
                    wal, workspace_fd, wal_name
                )
            if not _probe_catalog_source_is_unchanged(
                parent_fd, path.name, source_files, expected_family
            ):
                raise QualificationRefused("qualification probe catalog changed")

            connection = sqlite3.connect(
                f"file:/proc/self/fd/{workspace_fd}/{path.name}"
                "?mode=ro&cache=private",
                uri=True,
                timeout=30,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
                raise QualificationRefused(
                    "qualification probe catalog is not read-only"
                )
            connection.execute("BEGIN")
            check = connection.execute("PRAGMA quick_check").fetchall()
            version = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchall()
            rows = connection.execute(
                "SELECT job_id,sequence,physical_label,tape_serial "
                "FROM automatic_cassettes WHERE job_id=? AND sequence=?",
                (job_id, cassette_sequence),
            ).fetchall()
            if (
                len(check) != 1
                or check[0][0] != "ok"
                or len(version) != 1
                or version[0]["value"] != str(SCHEMA_VERSION)
                or len(rows) != 1
            ):
                raise QualificationRefused(
                    "qualification probe catalog identity is unavailable"
                )
            result = dict(rows[0])
            connection.rollback()
            connection.close()
            connection = None
            for name, (descriptor, before, digest) in snapshot_files.items():
                if (
                    _private_probe_file_snapshot(os.fstat(descriptor))
                    != before[:-1]
                    or _private_probe_file_snapshot(
                        os.stat(name, dir_fd=workspace_fd, follow_symlinks=False)
                    )
                    != before[:-1]
                    or _probe_fd_sha256(descriptor, before[6]) != digest
                ):
                    raise QualificationRefused(
                        "qualification probe snapshot changed"
                    )
            if not _probe_catalog_source_is_unchanged(
                parent_fd, path.name, source_files, expected_family
            ):
                raise QualificationRefused("qualification probe catalog changed")
            return result
    except (KeyError, OSError, sqlite3.Error, ValueError, TypeError):
        raise QualificationRefused("qualification probe catalog is unavailable") from None
    finally:
        if connection is not None:
            connection.close()
        for descriptor, _, _ in snapshot_files.values():
            os.close(descriptor)
        for descriptor, _, _ in source_files.values():
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def _create_plan(arguments: argparse.Namespace, *, now_ns: int, run_id: str) -> bytes:
    if (
        type(arguments.expires_seconds) is not int
        or not 1 <= arguments.expires_seconds <= 86_400
        or not arguments.catalog.is_absolute()
    ):
        raise QualificationRefused("qualification plan arguments are invalid")
    if "format" in arguments.operation and arguments.expected_mam_medium_serial is None:
        raise QualificationRefused(
            "format planning requires an explicit MAM medium serial"
        )
    with Catalog(arguments.catalog) as catalog:
        matches = [
            dict(row)
            for row in catalog.list_automatic_cassettes(arguments.job_id)
            if row["sequence"] == arguments.cassette_sequence
        ]
    if len(matches) != 1:
        raise QualificationRefused("catalog cassette identity is unavailable")
    plan = QualificationPlan.from_catalog(
        matches[0],
        run_id=run_id,
        expected_physical_label=arguments.expected_label,
        expected_mam_medium_serial=arguments.expected_mam_medium_serial,
        drive_serial=arguments.drive_serial,
        drive_wwid=arguments.drive_wwid,
        linux_tree_sha256=arguments.linux_tree_sha256,
        ltfs_tree_sha256=arguments.ltfs_tree_sha256,
        ltfs_rpm_sha256=arguments.ltfs_rpm_sha256,
        issued_at_ns=now_ns,
        expires_at_ns=now_ns + arguments.expires_seconds * 1_000_000_000,
        operations=tuple(
            QualificationOperation(operation) for operation in arguments.operation
        ),
    )
    return plan.canonical_bytes()


def _revalidate_catalog(plan: QualificationPlan, catalog_path: Path) -> None:
    if not catalog_path.is_absolute():
        raise QualificationRefused("qualification catalog path is invalid")
    with Catalog(catalog_path) as catalog:
        matches = [
            row
            for row in catalog.list_automatic_cassettes(plan.job_id)
            if row["sequence"] == plan.cassette_sequence
        ]
    if (
        len(matches) != 1
        or matches[0]["physical_label"] != plan.physical_label
        or matches[0]["tape_serial"] != plan.tape_serial
    ):
        raise QualificationRefused("qualification catalog identity changed")


def _next_operation(
    plan: QualificationPlan, catalog_path: Path
) -> QualificationOperation:
    ordered = _qualification_operation_order(plan)
    if not ordered:
        raise QualificationRefused("qualification plan has no executable operation")
    with Catalog(catalog_path) as catalog:
        run = catalog.connection.execute(
            "SELECT plan_sha256,plan_json,status FROM ltfs_qualification_runs "
            "WHERE run_id=?",
            (plan.run_id,),
        ).fetchone()
        if run is None:
            expected = ordered[0]
        else:
            rows = catalog.connection.execute(
                "SELECT ordinal,operation,request_sha256,dispatched,"
                "terminal_receipt_sha256,child_exit_code,verdict "
                "FROM ltfs_qualification_stages WHERE run_id=? ORDER BY ordinal",
                (plan.run_id,),
            ).fetchall()
            if (
                run["plan_sha256"] != plan.plan_sha256
                or run["plan_json"] != plan.canonical_bytes().decode("utf-8")
                or run["status"] not in {"planned", "running"}
                or len(rows) % 2
            ):
                raise QualificationRefused(
                    "qualification durable sequence is unavailable"
                )
            completed: list[QualificationOperation] = []
            for index, (dispatch, terminal) in enumerate(
                zip(rows[::2], rows[1::2], strict=True)
            ):
                try:
                    operation = QualificationOperation(dispatch["operation"])
                except ValueError:
                    raise QualificationRefused(
                        "qualification durable sequence is invalid"
                    ) from None
                if (
                    index >= len(ordered)
                    or operation is not ordered[index]
                    or terminal["operation"] != dispatch["operation"]
                    or terminal["request_sha256"] != dispatch["request_sha256"]
                    or dispatch["dispatched"] != 1
                    or dispatch["verdict"] != "dispatch_started"
                    or dispatch["terminal_receipt_sha256"] is not None
                    or dispatch["child_exit_code"] is not None
                    or terminal["dispatched"] != 1
                    or terminal["verdict"] != "pass"
                    or terminal["terminal_receipt_sha256"] is None
                    or type(terminal["child_exit_code"]) is not int
                ):
                    raise QualificationRefused(
                        "qualification durable sequence is invalid"
                    )
                completed.append(operation)
            if len(completed) >= len(ordered):
                raise QualificationRefused("qualification plan is already complete")
            expected = ordered[len(completed)]
    return expected


def _require_next_operation(
    plan: QualificationPlan,
    catalog_path: Path,
    requested: QualificationOperation,
) -> None:
    if requested is not _next_operation(plan, catalog_path):
        raise QualificationRefused("qualification operation is out of sequence")


def _qualification_operation_order(
    plan: QualificationPlan,
) -> tuple[QualificationOperation, ...]:
    if any(
        operation not in SUPPORTED_QUALIFICATION_OPERATIONS
        for operation in plan.operations
    ):
        raise QualificationRefused("qualification operation is unsupported")
    return tuple(
        operation for operation in _EXECUTION_ORDER if operation in plan.operations
    )


def _evidence_matches_plan(evidence: object, plan: QualificationPlan) -> bool:
    return type(evidence) is QualificationEnvironmentEvidence and (
        evidence.physical_label,
        evidence.tape_serial,
        evidence.drive_serial,
        evidence.drive_wwid,
        evidence.linux_tree_sha256,
        evidence.ltfs_tree_sha256,
        evidence.ltfs_rpm_sha256,
    ) == (
        plan.physical_label,
        plan.tape_serial,
        plan.drive_serial,
        plan.drive_wwid,
        plan.linux_tree_sha256,
        plan.ltfs_tree_sha256,
        plan.ltfs_rpm_sha256,
    )


def _validate_post_operation_identity(
    operation: QualificationOperation,
    before: QualificationEnvironmentEvidence,
    after: QualificationEnvironmentEvidence,
) -> None:
    if (
        after.tape_device_identity_sha256 != before.tape_device_identity_sha256
        or after.scsi_device_identity_sha256 != before.scsi_device_identity_sha256
    ):
        raise QualificationRefused("qualification device identity changed")
    if operation is QualificationOperation.FORMAT:
        valid = (
            after.volume_uuid is not None
            and type(after.generation) is int
            and after.generation > 0
            and (before.volume_uuid is None or after.volume_uuid != before.volume_uuid)
        )
    elif operation in {
        QualificationOperation.READ_ONLY,
        QualificationOperation.LOAD,
    }:
        valid = (
            (after.volume_uuid, after.generation)
            == (
                before.volume_uuid,
                before.generation,
            )
            and after.observed_media_identity_sha256
            == before.observed_media_identity_sha256
        )
    elif operation in {
        QualificationOperation.ADDITIVE_WRITE,
        QualificationOperation.OVERWRITE,
    }:
        valid = (
            before.volume_uuid is not None
            and after.volume_uuid == before.volume_uuid
            and type(before.generation) is int
            and type(after.generation) is int
            and after.generation > before.generation
            and after.observed_media_identity_sha256
            == before.observed_media_identity_sha256
        )
    elif operation is QualificationOperation.REPAIR:
        valid = (
            before.volume_uuid is not None
            and after.volume_uuid == before.volume_uuid
            and type(before.generation) is int
            and type(after.generation) is int
            and after.generation >= before.generation
            and after.observed_media_identity_sha256
            == before.observed_media_identity_sha256
        )
    else:
        raise QualificationRefused(
            "qualification post-operation evidence is unexpected"
        )
    if not valid:
        raise QualificationRefused("qualification post-operation identity changed")


def _record_dispatch_started(
    catalog_path: Path,
    plan: QualificationPlan,
    operation: QualificationOperation,
    request: BrokerQualificationRequest,
    evidence: QualificationEnvironmentEvidence,
) -> None:
    with Catalog(catalog_path) as catalog:
        existing = catalog.connection.execute(
            "SELECT 1 FROM ltfs_qualification_runs WHERE run_id=?", (plan.run_id,)
        ).fetchone()
        if existing is None:
            catalog.create_ltfs_qualification_run(plan)
        ordinal = catalog.connection.execute(
            "SELECT COALESCE(MAX(ordinal),0)+1 FROM ltfs_qualification_stages "
            "WHERE run_id=?",
            (plan.run_id,),
        ).fetchone()[0]
        catalog.record_ltfs_qualification_stage(
            run_id=plan.run_id,
            ordinal=ordinal,
            operation=operation,
            request_sha256=request.request_sha256,
            dispatched=True,
            terminal_receipt_sha256=None,
            child_exit_code=None,
            before_volume_uuid=evidence.volume_uuid,
            before_generation=evidence.generation,
            after_volume_uuid=None,
            after_generation=None,
            content_manifest_sha256=None,
            verdict="dispatch_started",
        )


def _record_terminal(
    catalog_path: Path,
    plan: QualificationPlan,
    operation: QualificationOperation,
    request: BrokerQualificationRequest,
    before: QualificationEnvironmentEvidence,
    after: QualificationEnvironmentEvidence | None,
    dispatch,
) -> None:
    content_operations = {
        QualificationOperation.READ_ONLY,
        QualificationOperation.ADDITIVE_WRITE,
        QualificationOperation.OVERWRITE,
        QualificationOperation.REPAIR,
    }
    with Catalog(catalog_path) as catalog:
        ordinal = catalog.connection.execute(
            "SELECT COALESCE(MAX(ordinal),0)+1 FROM ltfs_qualification_stages "
            "WHERE run_id=?",
            (plan.run_id,),
        ).fetchone()[0]
        catalog.record_ltfs_qualification_stage(
            run_id=plan.run_id,
            ordinal=ordinal,
            operation=operation,
            request_sha256=request.request_sha256,
            dispatched=True,
            terminal_receipt_sha256=dispatch.terminal_receipt_sha256,
            child_exit_code=dispatch.child_exit_code,
            before_volume_uuid=before.volume_uuid,
            before_generation=before.generation,
            after_volume_uuid=None if after is None else after.volume_uuid,
            after_generation=None if after is None else after.generation,
            content_manifest_sha256=(
                dispatch.evidence_sha256 if operation in content_operations else None
            ),
            verdict="pass",
        )
        if operation is _qualification_operation_order(plan)[-1]:
            catalog.complete_ltfs_qualification_run(plan.run_id)


def _fence_run(catalog_path: Path, run_id: str) -> None:
    try:
        with Catalog(catalog_path) as catalog:
            catalog.fence_ltfs_qualification_run(
                run_id, "ambiguous_or_invalid_terminal_evidence"
            )
    except (CatalogError, OSError, ValueError):
        pass


@contextmanager
def _open_pinned_catalog(path: Path) -> Iterator[Catalog]:
    """Open an existing regular catalog through a held no-follow descriptor."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise QualificationRefused("qualification catalog path is invalid")
    descriptor = -1
    catalog = None
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise QualificationRefused("qualification catalog file is invalid")
        catalog = Catalog(Path(f"/proc/self/fd/{descriptor}"))
        if _file_snapshot(os.fstat(descriptor)) != _file_snapshot(before):
            raise QualificationRefused("qualification catalog file changed")
        yield catalog
    except OSError:
        raise QualificationRefused("qualification catalog is unavailable") from None
    finally:
        if catalog is not None:
            catalog.close()
        if descriptor >= 0:
            os.close(descriptor)


def _revalidate_open_catalog(plan: QualificationPlan, catalog: Catalog) -> None:
    matches = [
        row
        for row in catalog.list_automatic_cassettes(plan.job_id)
        if row["sequence"] == plan.cassette_sequence
    ]
    if (
        len(matches) != 1
        or matches[0]["physical_label"] != plan.physical_label
        or matches[0]["tape_serial"] != plan.tape_serial
    ):
        raise QualificationRefused("qualification catalog identity changed")


def _reconciliation_target(
    plan: QualificationPlan, catalog: Catalog
) -> tuple[QualificationOperation, str, int]:
    run = catalog.connection.execute(
        "SELECT plan_sha256,plan_json,status,fence_reason,fenced_at "
        "FROM ltfs_qualification_runs WHERE run_id=?",
        (plan.run_id,),
    ).fetchone()
    rows = catalog.connection.execute(
        "SELECT ordinal,operation,request_sha256,dispatched,"
        "terminal_receipt_sha256,child_exit_code,verdict "
        "FROM ltfs_qualification_stages WHERE run_id=? ORDER BY ordinal",
        (plan.run_id,),
    ).fetchall()
    ordered = _qualification_operation_order(plan)
    if (
        run is None
        or run["plan_sha256"] != plan.plan_sha256
        or run["plan_json"] != plan.canonical_bytes().decode("utf-8")
        or run["status"] != "fenced"
        or type(run["fence_reason"]) is not str
        or not run["fence_reason"]
        or type(run["fenced_at"]) is not str
        or not run["fenced_at"]
        or not rows
        or len(rows) % 2 != 1
    ):
        raise QualificationRefused(
            "qualification durable reconciliation is unavailable"
        )
    completed: list[QualificationOperation] = []
    for index, (dispatch, terminal) in enumerate(
        zip(rows[:-1:2], rows[1:-1:2], strict=True)
    ):
        try:
            operation = QualificationOperation(dispatch["operation"])
        except ValueError:
            raise QualificationRefused(
                "qualification durable reconciliation is invalid"
            ) from None
        if (
            index >= len(ordered)
            or operation is not ordered[index]
            or dispatch["ordinal"] != 2 * index + 1
            or terminal["ordinal"] != dispatch["ordinal"] + 1
            or terminal["operation"] != dispatch["operation"]
            or terminal["request_sha256"] != dispatch["request_sha256"]
            or dispatch["dispatched"] != 1
            or dispatch["verdict"] != "dispatch_started"
            or dispatch["terminal_receipt_sha256"] is not None
            or dispatch["child_exit_code"] is not None
            or terminal["dispatched"] != 1
            or terminal["verdict"] != "pass"
            or terminal["terminal_receipt_sha256"] is None
            or type(terminal["child_exit_code"]) is not int
        ):
            raise QualificationRefused(
                "qualification durable reconciliation is invalid"
            )
        completed.append(operation)
    final = rows[-1]
    try:
        operation = QualificationOperation(final["operation"])
    except ValueError:
        raise QualificationRefused(
            "qualification durable reconciliation is invalid"
        ) from None
    if (
        len(completed) >= len(ordered)
        or operation is not ordered[len(completed)]
        or final["ordinal"] != 2 * len(completed) + 1
        or final["dispatched"] != 1
        or final["verdict"] != "dispatch_started"
        or final["terminal_receipt_sha256"] is not None
        or final["child_exit_code"] is not None
    ):
        raise QualificationRefused("qualification durable reconciliation is invalid")
    return operation, final["request_sha256"], _EXECUTION_ORDER.index(operation) + 1


def _canonical_ltfs_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return (
        str(parsed) == value
        and parsed.variant == uuid.RFC_4122
        and parsed.version in {1, 2, 3, 4, 5}
    )


def _validate_reconciliation_postcondition(
    operation: QualificationOperation,
    snapshot: Mapping[str, object],
    evidence: QualificationEnvironmentEvidence,
) -> None:
    if (
        type(operation) is not QualificationOperation
        or not isinstance(snapshot, Mapping)
        or type(evidence) is not QualificationEnvironmentEvidence
        or evidence.physical_label != snapshot.get("expected_physical_label")
        or evidence.tape_serial != snapshot.get("expected_tape_serial")
        or evidence.drive_serial != snapshot.get("expected_drive_serial")
        or evidence.drive_wwid != snapshot.get("expected_drive_wwid")
        or evidence.tape_device_identity_sha256
        != snapshot.get("tape_device_identity_sha256")
        or evidence.scsi_device_identity_sha256
        != snapshot.get("scsi_device_identity_sha256")
    ):
        raise QualificationRefused("qualification reconciliation identity changed")
    before_uuid = snapshot.get("expected_volume_uuid")
    before_generation = snapshot.get("expected_generation")
    if operation is QualificationOperation.FORMAT:
        valid = (
            _canonical_ltfs_uuid(evidence.volume_uuid)
            and type(evidence.generation) is int
            and 0 < evidence.generation < 1 << 64
            and (before_uuid is None or evidence.volume_uuid != before_uuid)
        )
    elif operation in {
        QualificationOperation.READ_ONLY,
        QualificationOperation.LOAD,
    }:
        valid = (
            evidence.volume_uuid == before_uuid
            and evidence.generation == before_generation
            and evidence.observed_media_identity_sha256
            == snapshot.get("observed_media_identity_sha256")
        )
    elif operation in {
        QualificationOperation.ADDITIVE_WRITE,
        QualificationOperation.OVERWRITE,
    }:
        valid = (
            _canonical_ltfs_uuid(before_uuid)
            and evidence.volume_uuid == before_uuid
            and type(before_generation) is int
            and type(evidence.generation) is int
            and before_generation < evidence.generation < 1 << 64
            and evidence.observed_media_identity_sha256
            == snapshot.get("observed_media_identity_sha256")
        )
    elif operation is QualificationOperation.REPAIR:
        valid = (
            _canonical_ltfs_uuid(before_uuid)
            and evidence.volume_uuid == before_uuid
            and type(before_generation) is int
            and type(evidence.generation) is int
            and before_generation <= evidence.generation < 1 << 64
            and evidence.observed_media_identity_sha256
            == snapshot.get("observed_media_identity_sha256")
        )
    else:
        valid = evidence.volume_uuid is None and evidence.generation is None
    if not valid:
        raise QualificationRefused("qualification reconciliation postcondition failed")


def _validate_terminal_inspection(
    plan: QualificationPlan,
    operation: QualificationOperation,
    request_sha256: str,
    request: BrokerQualificationInspectionRequest,
    inspection: BrokerQualificationInspection,
) -> Mapping[str, object]:
    if (
        type(inspection) is not BrokerQualificationInspection
        or inspection.state != "terminal"
        or inspection.stage_snapshot is None
        or inspection.dispatch is None
    ):
        raise QualificationRefused("qualification broker evidence is not terminal")
    snapshot = inspection.stage_snapshot
    dispatch = inspection.dispatch
    if (
        request.run_id != plan.run_id
        or snapshot["run_id"] != plan.run_id
        or dispatch.run_id != plan.run_id
        or request.stage_ordinal != snapshot["stage_ordinal"]
        or request.stage_ordinal != dispatch.stage_ordinal
        or snapshot["plan_sha256"] != plan.plan_sha256
        or snapshot["operation"] != operation.value
        or dispatch.operation is not operation
        or snapshot["request_sha256"] != request_sha256
        or dispatch.request_sha256 != request_sha256
        or dispatch.dispatch_state != "terminal"
    ):
        raise QualificationRefused("qualification broker evidence was substituted")
    return snapshot


def _reconcile_stage(
    arguments: argparse.Namespace, output: TextIO, *, current_time_ns: int
) -> int:
    if _effective_ids() != (0, 0):
        raise QualificationRefused("qualification reconciliation requires root")
    if not all(
        isinstance(path, Path) and path.is_absolute()
        for path in (arguments.catalog, arguments.plan, arguments.credential)
    ):
        raise QualificationRefused("qualification reconciliation path is invalid")
    plan = _read_plan(arguments.plan)
    if not plan.issued_at_ns <= current_time_ns < plan.expires_at_ns:
        raise QualificationRefused("qualification reconciliation plan is stale")
    with _open_pinned_catalog(arguments.catalog) as catalog:
        _revalidate_open_catalog(plan, catalog)
        operation, request_sha256, broker_stage_ordinal = _reconciliation_target(
            plan, catalog
        )
        inspection_request = BrokerQualificationInspectionRequest(
            run_id=plan.run_id,
            stage_ordinal=broker_stage_ordinal,
            challenge=secrets.token_bytes(32),
        )
        inspection = _connect_broker(
            arguments.credential
        ).inspect_ltfs_qualification_stage(inspection_request)
        snapshot = _validate_terminal_inspection(
            plan,
            operation,
            request_sha256,
            inspection_request,
            inspection,
        )
        evidence = _prepare_reconciliation_environment(
            plan, operation, snapshot, arguments.catalog
        )
        if not _evidence_matches_plan(evidence, plan):
            raise QualificationRefused(
                "qualification reconciliation environment changed"
            )
        _validate_reconciliation_postcondition(operation, snapshot, evidence)
        catalog.reconcile_ltfs_qualification_stage(
            plan=plan,
            inspection_request=inspection_request,
            inspection=inspection,
            physical_label=evidence.physical_label,
            tape_serial=evidence.tape_serial,
            drive_serial=evidence.drive_serial,
            drive_wwid=evidence.drive_wwid,
            tape_device_identity_sha256=evidence.tape_device_identity_sha256,
            scsi_device_identity_sha256=evidence.scsi_device_identity_sha256,
            expected_media_scope_sha256=evidence.expected_media_scope_sha256,
            observed_media_identity_sha256=evidence.observed_media_identity_sha256,
            volume_uuid=evidence.volume_uuid,
            generation=evidence.generation,
        )
    output.write(
        json.dumps(
            {
                "operation": operation.value,
                "reconciled": True,
                "run_id": plan.run_id,
                "stage_ordinal": broker_stage_ordinal,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    return 0


def _execute_stage(
    arguments: argparse.Namespace, output: TextIO, *, current_time_ns: int
) -> int:
    if _effective_ids() != (0, 0):
        raise QualificationRefused("qualification execution requires root")
    plan = _read_plan(arguments.plan)
    operation = QualificationOperation(arguments.operation)
    credential = _read_root_credential(arguments.credential)
    plan.verify_token(operation, arguments.token, credential, now_ns=current_time_ns)
    _revalidate_catalog(plan, arguments.catalog)
    _require_next_operation(plan, arguments.catalog, operation)
    evidence = _prepare_environment(plan, operation, arguments.catalog)
    if not _evidence_matches_plan(evidence, plan):
        raise QualificationRefused("qualification environment changed")
    unsigned_request = BrokerQualificationRequest(
        protocol_version=plan.schema,
        run_id=plan.run_id,
        plan_sha256=plan.plan_sha256,
        stage_ordinal=_EXECUTION_ORDER.index(operation) + 1,
        operation=operation,
        operation_token="0" * 64,
        tape_device_identity_sha256=evidence.tape_device_identity_sha256,
        scsi_device_identity_sha256=evidence.scsi_device_identity_sha256,
        expected_media_scope_sha256=evidence.expected_media_scope_sha256,
        observed_media_identity_sha256=evidence.observed_media_identity_sha256,
        expected_physical_label=plan.physical_label,
        expected_tape_serial=plan.tape_serial,
        expected_drive_serial=plan.drive_serial,
        expected_drive_wwid=plan.drive_wwid,
        expected_volume_uuid=evidence.volume_uuid,
        expected_generation=evidence.generation,
        issued_at_ns=plan.issued_at_ns,
        expires_at_ns=plan.expires_at_ns,
        request_nonce=secrets.token_bytes(32),
        canonical_plan_json=plan.canonical_bytes().decode("utf-8")
        if plan.schema == 2
        else None,
    )
    request = replace(
        unsigned_request,
        operation_token=qualification_request_operation_token(
            unsigned_request, credential
        ),
    )
    _record_dispatch_started(arguments.catalog, plan, operation, request, evidence)
    try:
        dispatch = _connect_broker().execute_ltfs_qualification_stage(request)
        after = (
            _prepare_environment(
                plan, QualificationOperation.READ_ONLY, arguments.catalog
            )
            if operation in {QualificationOperation.FORMAT, QualificationOperation.LOAD}
            else _prepare_environment(plan, operation, arguments.catalog)
            if operation
            in {
                QualificationOperation.READ_ONLY,
                QualificationOperation.ADDITIVE_WRITE,
                QualificationOperation.OVERWRITE,
                QualificationOperation.REPAIR,
            }
            else None
        )
        if after is not None and not _evidence_matches_plan(after, plan):
            raise QualificationRefused("qualification post-operation identity changed")
        if after is not None:
            _validate_post_operation_identity(operation, evidence, after)
        _record_terminal(
            arguments.catalog,
            plan,
            operation,
            request,
            evidence,
            after,
            dispatch,
        )
    except BaseException:
        _fence_run(arguments.catalog, plan.run_id)
        raise
    output.write(
        json.dumps(
            {
                "child_exit_code": dispatch.child_exit_code,
                "dispatch_state": dispatch.dispatch_state,
                "evidence_sha256": dispatch.evidence_sha256,
                "operation": dispatch.operation.value,
                "request_sha256": dispatch.request_sha256,
                "run_id": dispatch.run_id,
                "stage_ordinal": dispatch.stage_ordinal,
                "terminal_receipt_sha256": dispatch.terminal_receipt_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    return 0


def main(
    argv: list[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    now_ns=time.time_ns,
    run_id_factory=lambda: str(uuid.uuid4()),
) -> int:
    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    events = JournalOperationalEventSink(
        syslog_identifier="lto-archiver-ltfs-qualification"
    )
    try:
        events.emit(
            OperationalEvent(
                OperationalSource.QUALIFICATION,
                OperationalSeverity.INFO,
                "qualification.started",
                "LTFS qualification started.",
            )
        )
    except BaseException:  # noqa: BLE001 - diagnostics never alter qualification
        pass
    finished = False

    def finish(result: int) -> int:
        nonlocal finished
        if finished:
            return result
        finished = True
        try:
            events.emit(
                OperationalEvent(
                    OperationalSource.QUALIFICATION,
                    (
                        OperationalSeverity.INFO
                        if result == 0
                        else OperationalSeverity.ERROR
                    ),
                    "qualification.succeeded" if result == 0 else "qualification.failed",
                    (
                        "LTFS qualification succeeded."
                        if result == 0
                        else "LTFS qualification failed."
                    ),
                    exit_code=result,
                )
            )
        except BaseException:  # noqa: BLE001 - diagnostics never alter qualification
            pass
        return result

    try:
        arguments_source = list(sys.argv[1:] if argv is None else argv)
        if not arguments_source or arguments_source[0].startswith("-"):
            arguments_source.insert(0, "plan")
        arguments = _parser().parse_args(arguments_source)
        if arguments.action == "probe":
            return finish(
                _probe_media(
                    arguments,
                    output,
                    now_ns=now_ns(),
                    run_id=str(run_id_factory()),
                )
            )
        if arguments.action == "plan":
            issued_at = now_ns()
            payload = _create_plan(
                arguments, now_ns=issued_at, run_id=str(run_id_factory())
            )
            output.write(payload.decode("utf-8") + "\n")
            return finish(0)
        if arguments.action == "authorize":
            if _effective_ids() != (0, 0):
                raise QualificationRefused("qualification authorization requires root")
            plan = _read_plan(arguments.plan)
            credential = _read_root_credential(arguments.credential)
            token = plan.authorize(
                QualificationOperation(arguments.operation), credential
            )
            output.write(token)
            return finish(0)
        if arguments.action == "reconcile-stage":
            return finish(
                _reconcile_stage(arguments, output, current_time_ns=now_ns())
            )
        if arguments.action == "execute-approved-stage":
            if _effective_ids() != (0, 0):
                raise QualificationRefused("qualification execution requires root")
            plan = _read_plan(_ACTIVE_PLAN)
            operation = _next_operation(plan, _ACTIVE_CATALOG)
            sealed = argparse.Namespace(
                catalog=_ACTIVE_CATALOG,
                plan=_ACTIVE_PLAN,
                operation=operation.value,
                token=_read_operation_token(_OPERATION_TOKEN),
                credential=_QUALIFICATION_CREDENTIAL,
            )
            return finish(
                _execute_stage(sealed, output, current_time_ns=now_ns())
            )
        if arguments.action == "execute-stage":
            return finish(
                _execute_stage(arguments, output, current_time_ns=now_ns())
            )
        raise QualificationRefused("qualification action is unsupported")
    except (BrokerUnavailable, CatalogError, QualificationRefused, OSError, ValueError):
        errors.write("LTFS qualification refused\n")
        return finish(2)
    except BaseException:
        finish(2)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
