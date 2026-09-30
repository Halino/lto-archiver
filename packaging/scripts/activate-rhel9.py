#!/usr/bin/python3.11
from __future__ import annotations

import argparse
import contextlib
import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

CONFIGURATOR = "/usr/libexec/lto-archiver/configure-device-policy.py"
FIREWALL_CONFIGURATOR = "/usr/libexec/lto-archiver/configure-web-firewall-rhel9.py"
RESTORECON = "/usr/sbin/restorecon"
SYSTEMCTL = "/usr/bin/systemctl"
PYTHON = "/usr/bin/python3.11"
WEB_CONFIG = Path("/etc/lto-archiver/web.toml")
_APPLICATION_IMPORT_PROBE = (
    "import pathlib,sys;"
    "sys.dont_write_bytecode=True;"
    "sys.path.insert(0,'/usr/lib64/lto-archiver/python-runtime/3.11/site-packages');"
    "sys.path.insert(0,'/usr/lib/python3.11/site-packages');"
    "import ltobackup.catalog as catalog;"
    "origin=pathlib.Path(catalog.__file__).resolve();"
    "expected=pathlib.Path('/usr/lib/python3.11/site-packages');"
    "raise SystemExit(0 if origin.is_relative_to(expected) "
    "and catalog.SCHEMA_VERSION == 41 else 2)"
)
_APPLICATION_IMPORT_COMMAND = (PYTHON, "-I", "-c", _APPLICATION_IMPORT_PROBE)
_DROPIN_DIRECTORIES = (
    "/etc/systemd/system/lto-archiver-archive-runner-qualification.service.d",
    "/etc/systemd/system/lto-archiver-command-broker.service.d",
    "/etc/systemd/system/lto-archiverd.service.d",
)
_RESTORE_PATHS = (
    *_DROPIN_DIRECTORIES,
    "/etc/lto-archiver/web.toml",
    "/etc/lto-archiver/tls",
    "/usr/libexec/lto-archiver/run-web-rhel9.py",
    "/usr/bin/lto-archiver-log-reader",
)
_SOCKET_UNITS = (
    "lto-archiver-command-broker.socket",
    "lto-archiver-share-broker.socket",
    "lto-archiver-log-reader.socket",
    "lto-archiverd.socket",
)
_MANAGED_UNITS = (
    "lto-archiver-command-broker.service",
    "lto-archiver-command-broker.socket",
    "lto-archiver-share-broker.service",
    "lto-archiver-share-broker.socket",
    "lto-archiver-log-reader.socket",
    "lto-archiver-log-reader.service",
    "lto-archiverd.service",
    "lto-archiverd.socket",
    "lto-archiver-web.service",
)
_ENABLE_UNITS = (*_SOCKET_UNITS, "lto-archiver-web.service")
_START_UNITS = _ENABLE_UNITS
_QUIESCENT_STATE = "loaded\ninactive\ndead\n"
_ENABLED_STATES = frozenset({"enabled", "enabled-runtime", "linked", "linked-runtime"})
_DISABLED_STATES = frozenset({"disabled", "static", "indirect", "generated", ""})
_ACTIVATION_STAGES = frozenset(
    {
        "input_validation",
        "quiescence_check",
        "enablement_snapshot",
        "device_policy_apply",
        "web_firewall_verify",
        "restore_contexts",
        "systemd_reload",
        "device_policy_verify",
        "application_import_verify",
        "unit_enable",
        "unit_start",
        "web_firewall_apply",
    }
)
_ACTIVATION_ERRORS = (
    OSError,
    subprocess.SubprocessError,
    RuntimeError,
    ValueError,
    TypeError,
)


class ActivationError(RuntimeError):
    """Activation failure containing only a closed, non-sensitive stage ID."""

    def __init__(self, stage: str, *, cleanup_failed: bool = False) -> None:
        if stage not in _ACTIVATION_STAGES or type(cleanup_failed) is not bool:
            raise ValueError("invalid activation diagnostic")
        self.stage = stage
        self.cleanup_failed = cleanup_failed
        detail = f"activation_stage={stage}"
        if cleanup_failed:
            detail = f"activation cleanup failed; {detail}"
        super().__init__(detail)

    def stderr_line(self) -> str:
        suffix = " cleanup=failed" if self.cleanup_failed else ""
        return f"RHEL activation failed stage={self.stage}{suffix}\n"


def _require_quiescence(
    run_command: Callable[..., subprocess.CompletedProcess[object]],
) -> None:
    for unit in _MANAGED_UNITS:
        result = run_command(
            (
                SYSTEMCTL,
                "show",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--value",
                unit,
            ),
            check=True,
            capture_output=True,
            text=True,
        )
        if getattr(result, "stdout", None) != _QUIESCENT_STATE:
            raise RuntimeError


def _enabled_units(
    run_command: Callable[..., subprocess.CompletedProcess[object]],
) -> set[str]:
    enabled: set[str] = set()
    for unit in _ENABLE_UNITS:
        result = run_command(
            (SYSTEMCTL, "is-enabled", unit),
            check=False,
            capture_output=True,
            text=True,
        )
        state = str(getattr(result, "stdout", "")).strip()
        if getattr(result, "returncode", 1) == 0 and state in _ENABLED_STATES:
            enabled.add(unit)
        elif state not in _DISABLED_STATES:
            raise RuntimeError
    return enabled


def activate(
    config: Path,
    *,
    web_config: Path = WEB_CONFIG,
    run_command: Callable[..., subprocess.CompletedProcess[object]] = subprocess.run,
    geteuid: Callable[[], int] = os.geteuid,
) -> None:
    if (
        geteuid() != 0
        or not isinstance(config, Path)
        or not config.is_absolute()
        or not isinstance(web_config, Path)
        or not web_config.is_absolute()
    ):
        raise ActivationError("input_validation")

    prior_enabled: set[str] = set()
    cleanup_required = False
    enable_attempted = False
    start_attempted = False
    commands: tuple[tuple[str, Sequence[str]], ...] = (
        ("device_policy_apply", (CONFIGURATOR, "--config", str(config))),
        (
            "web_firewall_verify",
            (
                FIREWALL_CONFIGURATOR,
                "--config",
                str(web_config),
                "--verify-only",
            ),
        ),
        (
            "restore_contexts",
            (RESTORECON, "-RF", *_RESTORE_PATHS),
        ),
        ("systemd_reload", (SYSTEMCTL, "daemon-reload")),
        (
            "device_policy_verify",
            (CONFIGURATOR, "--config", str(config), "--verify-only"),
        ),
        ("application_import_verify", _APPLICATION_IMPORT_COMMAND),
    )
    stage = "quiescence_check"
    try:
        _require_quiescence(run_command)
        stage = "enablement_snapshot"
        prior_enabled = _enabled_units(run_command)
        cleanup_required = True
        for stage, command in commands:
            run_command(command, check=True)
        stage = "unit_enable"
        enable_attempted = True
        run_command((SYSTEMCTL, "enable", *_ENABLE_UNITS), check=True)
        stage = "unit_start"
        start_attempted = True
        run_command((SYSTEMCTL, "start", *_START_UNITS), check=True)
        stage = "web_firewall_apply"
        run_command(
            (
                FIREWALL_CONFIGURATOR,
                "--config",
                str(web_config),
                "--apply",
            ),
            check=True,
        )
    except _ACTIVATION_ERRORS:
        if not cleanup_required:
            raise ActivationError(stage) from None
        cleanup_failed = False
        if start_attempted:
            try:
                run_command((SYSTEMCTL, "stop", *reversed(_START_UNITS)), check=True)
            except _ACTIVATION_ERRORS:
                cleanup_failed = True
        if enable_attempted:
            newly_enabled = tuple(
                unit for unit in _ENABLE_UNITS if unit not in prior_enabled
            )
            if newly_enabled:
                try:
                    run_command((SYSTEMCTL, "disable", *newly_enabled), check=True)
                except _ACTIVATION_ERRORS:
                    cleanup_failed = True
        try:
            _require_quiescence(run_command)
        except _ACTIVATION_ERRORS:
            cleanup_failed = True
        if enable_attempted:
            try:
                if _enabled_units(run_command) != prior_enabled:
                    cleanup_failed = True
            except _ACTIVATION_ERRORS:
                cleanup_failed = True
        raise ActivationError(stage, cleanup_failed=cleanup_failed) from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/lto-archiver/config.toml"),
    )
    parser.add_argument("--web-config", type=Path, default=WEB_CONFIG)
    try:
        args = parser.parse_args(argv)
        activate(args.config, web_config=args.web_config)
        return 0
    except ActivationError as error:
        with contextlib.suppress(OSError):
            sys.stderr.write(error.stderr_line())
        return 2
    except (OSError, RuntimeError, ValueError, TypeError):
        with contextlib.suppress(OSError):
            sys.stderr.write("RHEL activation failed\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
