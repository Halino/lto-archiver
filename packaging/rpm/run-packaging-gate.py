#!/usr/bin/python3.11
"""Run the repository-only RPM packaging suite and emit canonical evidence."""

from __future__ import annotations

import argparse
import json
import os
import sys
import unittest
from pathlib import Path

_ALLOWED_SKIPS = frozenset(
    {
        "tests.test_linux_packaging.LinuxPackagingTests."
        "test_built_rpm_payload_and_ltfs_info_dependency_when_provided"
    }
)


class RecordingResult(unittest.TextTestResult):
    """Expose stable skipped-test identities for signed gate evidence."""


def run_gate(
    source_root: Path,
    output: Path,
    *,
    repository_commit: str,
    builder_sha256: str,
    runner_sha256: str,
) -> dict[str, object]:
    source_root = source_root.resolve(strict=True)
    expected_test = source_root / "tests/test_linux_packaging.py"
    if (
        not source_root.is_dir()
        or not (source_root / ".git").exists()
        or not expected_test.is_file()
        or not output.is_absolute()
        or output.exists()
    ):
        raise RuntimeError
    sys.path[:] = [
        os.fspath(source_root),
        os.fspath(source_root / "src"),
        "/usr/lib64/lto-archiver/python-runtime/3.11/site-packages",
        *(
            item
            for item in sys.path
            if item
            and Path(item).is_absolute()
            and item not in {os.fspath(source_root), os.fspath(source_root / "src")}
        ),
    ]
    module = __import__("tests.test_linux_packaging", fromlist=["*"])
    if Path(module.__file__).resolve(strict=True) != expected_test.resolve(strict=True):
        raise RuntimeError
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    runner = unittest.TextTestRunner(
        stream=sys.stderr,
        verbosity=2,
        resultclass=RecordingResult,
    )
    result = runner.run(suite)
    skipped = sorted(test.id() for test, _reason in result.skipped)
    if (
        not result.wasSuccessful()
        or result.failures
        or result.errors
        or result.unexpectedSuccesses
        or not set(skipped).issubset(_ALLOWED_SKIPS)
    ):
        raise RuntimeError
    payload: dict[str, object] = {
        "builder_sha256": builder_sha256,
        "python": "/usr/bin/python3.11 -I",
        "repository_commit": repository_commit,
        "runner_sha256": runner_sha256,
        "schema_version": 1,
        "skipped_test_ids": skipped,
        "status": "passed",
        "test_command": "tests.test_linux_packaging",
        "test_module": "tests.test_linux_packaging",
        "tests_run": result.testsRun,
    }
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
        json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repository-commit", required=True)
    parser.add_argument("--builder-sha256", required=True)
    parser.add_argument("--runner-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        run_gate(
            args.source_root,
            args.output,
            repository_commit=args.repository_commit,
            builder_sha256=args.builder_sha256,
            runner_sha256=args.runner_sha256,
        )
        return 0
    except (OSError, RuntimeError, TypeError, ValueError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
