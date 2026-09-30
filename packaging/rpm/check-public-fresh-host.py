#!/usr/bin/env python3
"""Read-only, fail-closed preflight for a disposable public first install."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable, NamedTuple


class FreshHostError(RuntimeError):
    """The starting host state could not be established safely."""


class HostState(NamedTuple):
    installed_nevras: tuple[str, ...]
    existing_paths: tuple[str, ...]
    managed_units: tuple[str, ...]


_PACKAGE_NAMES = re.compile(r"(?:lto-archiver(?:-[a-z0-9-]+)?|lto-ltfs)\Z")
_UNIT_NAMES = re.compile(r"(?:lto-archiver[a-z0-9@_.-]*|lto-ltfs[a-z0-9@_.-]*)\Z")
_STATE_ROOTS = (
    "etc", "var/lib", "var/log", "run", "run/lock", "mnt",
)
_STATE_PATTERNS = ("lto-archiver*", "lto-ltfs*")
_EXACT_PATHS = ("etc/ltfs.conf",)
_SYSTEMD_ROOTS = ("etc/systemd/system", "run/systemd/system", "usr/lib/systemd/system")
_UNIT_PATTERNS = ("lto-archiver*", "lto-ltfs*")


def evaluate_fresh_host(state: HostState) -> tuple[str, ...]:
    """Return stable, exact reasons; this function performs no host I/O."""
    return tuple(sorted(
        [f"installed LTO package: {name}" for name in state.installed_nevras]
        + [f"existing LTO path: {path}" for path in state.existing_paths]
        + [f"managed LTO unit: {unit}" for unit in state.managed_units]
    ))


def _run_read_only(command: list[str]) -> bytes:
    try:
        return subprocess.run(command, check=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise FreshHostError(f"read-only host query failed: {command[0]}") from error


def _path_present(path: Path) -> bool:
    try:
        path.lstat()  # Also catches dangling symlinks; exists() does not.
        return True
    except FileNotFoundError:
        return False


def _unit_names(output: bytes) -> set[str]:
    try:
        lines = output.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise FreshHostError("invalid systemd unit listing") from error
    return {
        name for line in lines if (fields := line.split())
        if _UNIT_NAMES.fullmatch(name := fields[0])
    }


def collect_host_state(
    *, root: Path = Path("/"), runner: Callable[[list[str]], bytes] = _run_read_only
) -> HostState:
    """Observe installed packages, residual paths and inactive/active units only."""
    if root.is_symlink() or not root.is_dir():
        raise FreshHostError("host root is not an ordinary directory")
    try:
        rpm_lines = runner(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n"])
        packages: set[str] = set()
        for line in rpm_lines.decode("utf-8").splitlines():
            fields = line.split()
            if len(fields) != 2:
                raise FreshHostError("malformed RPM package inventory")
            if _PACKAGE_NAMES.fullmatch(fields[0]):
                packages.add(f"{fields[0]}-{fields[1]}")
        paths: set[str] = set()
        for relative in _EXACT_PATHS:
            if _path_present(root / relative):
                paths.add("/" + relative)
        for relative in _STATE_ROOTS + _SYSTEMD_ROOTS:
            parent = root / relative
            if not _path_present(parent):
                continue
            if parent.is_symlink() or not parent.is_dir():
                raise FreshHostError(f"unsafe host inventory root: /{relative}")
            patterns = _UNIT_PATTERNS if relative in _SYSTEMD_ROOTS else _STATE_PATTERNS
            for pattern in patterns:
                paths.update(
                    "/" + item.relative_to(root).as_posix()
                    for item in parent.glob(pattern)
                    if _path_present(item)
                )
        query = ["lto-archiver*", "lto-archiverd*", "lto-ltfs*"]
        units = _unit_names(runner([
            "systemctl", "list-unit-files", "--all", "--no-legend", "--no-pager", *query,
        ]))
        units |= _unit_names(runner([
            "systemctl", "list-units", "--all", "--full", "--plain",
            "--no-legend", "--no-pager", *query,
        ]))
        details: set[str] = set()
        for unit in sorted(units):
            output = runner([
                "systemctl", "show", "--property=Id,LoadState,ActiveState,UnitFileState", unit,
            ])
            fields = dict(
                line.split("=", 1) for line in output.decode("utf-8").splitlines()
                if "=" in line
            )
            if fields.get("Id") != unit or any(
                key not in fields for key in ("LoadState", "ActiveState", "UnitFileState")
            ):
                raise FreshHostError(f"incomplete systemd inventory: {unit}")
            details.add(
                f"{unit} (load={fields['LoadState']}, active={fields['ActiveState']}, "
                f"file={fields['UnitFileState']})"
            )
        return HostState(tuple(sorted(packages)), tuple(sorted(paths)), tuple(sorted(details)))
    except (OSError, UnicodeError) as error:
        raise FreshHostError("host inventory is unreadable") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the bounded admission report")
    args = parser.parse_args(argv)
    try:
        state = collect_host_state()
        reasons = evaluate_fresh_host(state)
    except FreshHostError as error:
        reasons = (str(error),)
        state = HostState((), (), ())
    report = {
        "schema_version": 1,
        "fresh": not reasons,
        "reasons": list(reasons),
        "installed_nevras": list(state.installed_nevras),
        "existing_paths": list(state.existing_paths),
        "managed_units": list(state.managed_units),
    }
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("clean disposable host" if not reasons else "fresh install refused: " + "; ".join(reasons))
    return 0 if not reasons else 2


if __name__ == "__main__":
    raise SystemExit(main())
