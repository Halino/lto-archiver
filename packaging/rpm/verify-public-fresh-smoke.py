#!/usr/bin/env python3
"""Admit the exact, separately approved sanitized disposable-VM smoke report.

This validates a report's bytes and claims. It cannot establish that the VM
checks actually ran; the release reviewer must inspect independent VM evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path


SHA = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
APP = "lto-archiver-0.11.30-155.el9.noarch.rpm"
RUNTIME = "lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm"
DRIVER = "lto-ltfs-0.1.2-22.el9.x86_64.rpm"
FIELDS = frozenset({
    "schema_version", "profile", "qualified", "app_commit", "driver_commit",
    "rpm_sha256", "baseline_sha256", "restored_sha256", "checks",
    "uninstall_generated_state_count",
    "unverified_features",
})
CHECKS = frozenset({
    "disposable_marker", "snapshot_created", "fresh_host", "signed_tuple",
    "install_order", "installed_nevras", "rpm_verify", "unit_syntax",
    "service_accounts", "selinux", "live_web_login", "hardware_absence_refused",
    "uninstall_residue_recorded", "uninstall_no_owned_executables",
    "uninstall_no_active_units", "snapshot_restored",
})
UNVERIFIED = ("backup_restore", "daemon_import", "physical_ltfs")


class SmokeReportError(ValueError):
    """Report is missing, unsafe, unqualified or differs from approval."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise SmokeReportError("duplicate report key")
        value[key] = item
    return value


def _ordinary_bytes(path: Path, limit: int | None = None) -> bytes:
    try:
        status = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise SmokeReportError("unsafe report or RPM file")
        if limit is not None and status.st_size > limit:
            raise SmokeReportError("smoke report exceeds size limit")
        return path.read_bytes()
    except OSError as error:
        raise SmokeReportError("unreadable report or RPM file") from error


def verify_report(
    report: Path, approved_sha256: str, app_commit: str,
    app_rpm: Path, runtime_rpm: Path,
) -> dict[str, object]:
    """Require exact approved bytes, identity and every runtime/restore claim."""
    if SHA.fullmatch(approved_sha256) is None or COMMIT.fullmatch(app_commit) is None:
        raise SmokeReportError("invalid approval identity")
    raw = _ordinary_bytes(report, 16_384)
    if hashlib.sha256(raw).hexdigest() != approved_sha256:
        raise SmokeReportError("smoke report bytes differ from approval")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SmokeReportError("malformed smoke report") from error
    if type(value) is not dict or set(value) != FIELDS:
        raise SmokeReportError("smoke report field closure differs")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 2
            or value["profile"] != "fresh-rhel9-webui-hardware-absent"
            or value["unverified_features"] != list(UNVERIFIED)
            or value["qualified"] is not True
            or value["app_commit"] != app_commit
            or type(value["driver_commit"]) is not str
            or COMMIT.fullmatch(value["driver_commit"]) is None):
        raise SmokeReportError("smoke report is not qualified for this source")
    checks = value["checks"]
    if type(checks) is not dict or set(checks) != CHECKS or any(
        flag is not True for flag in checks.values()
    ):
        raise SmokeReportError("required VM smoke check failed or is missing")
    hashes = value["rpm_sha256"]
    if type(hashes) is not dict or set(hashes) != {APP, RUNTIME, DRIVER} or any(
        type(digest) is not str or SHA.fullmatch(digest) is None
        for digest in hashes.values()
    ):
        raise SmokeReportError("signed RPM tuple is incomplete")
    for name, path in ((APP, app_rpm), (RUNTIME, runtime_rpm)):
        if path.name != name or hashlib.sha256(_ordinary_bytes(path)).hexdigest() != hashes[name]:
            raise SmokeReportError("smoke RPM differs from verified candidate")
    baseline = value["baseline_sha256"]
    restored = value["restored_sha256"]
    if (type(baseline) is not str or SHA.fullmatch(baseline) is None
            or baseline != restored):
        raise SmokeReportError("VM baseline was not restored")
    count = value["uninstall_generated_state_count"]
    if type(count) is not int or not 0 <= count <= 1_000_000:
        raise SmokeReportError("invalid uninstall observation")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--approved-sha256", required=True)
    parser.add_argument("--app-commit", required=True)
    parser.add_argument("--app-rpm", type=Path, required=True)
    parser.add_argument("--runtime-rpm", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        verify_report(args.report, args.approved_sha256, args.app_commit,
                      args.app_rpm, args.runtime_rpm)
    except SmokeReportError as error:
        print(f"fresh VM smoke refused: {error}", file=sys.stderr)
        return 2
    print("approved fresh VM smoke report admitted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
