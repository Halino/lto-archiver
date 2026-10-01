"""Passively observe the frozen boundary browser test; print bounded JSON."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest


SUBJECT_COMMIT = "4507cd23e96fef48dd3099d0da69bb7cda3a9a27"
TEST_NAME = (
    "tests.test_boundary_status_browser.BoundaryStatusBrowserTests."
    "test_live_patch_preserves_panel_and_paused_deficit_in_narrow_layout"
)
OUTPUT_LIMIT = 8192


def bounded_output(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return {"type": "bytes", "length": len(value),
                "prefix_base64": base64.b64encode(value[:OUTPUT_LIMIT]).decode("ascii")}
    return {"type": "text", "length": len(value), "prefix": value[:OUTPUT_LIMIT]}


def run_diagnostic(suite, metadata, *, stream=sys.stdout):
    """Observe one unittest without changing its outcome or subprocess calls."""
    started = time.monotonic()
    report = {"selected_tests": suite.countTestCases(), "tests_run": 0,
              "failures": 0, "errors": 0, "skipped": 0,
              "test_successful": None, "metadata": {},
              "process_errors": [], "diagnostic_errors": []}

    class Observer(unittest.TextTestResult):
        def addError(self, test, err):
            error = err[1]
            if isinstance(error, (subprocess.TimeoutExpired, subprocess.CalledProcessError)):
                report["process_errors"].append({
                    "test": test.id(), "exception": type(error).__name__,
                    "timeout": getattr(error, "timeout", None),
                    "returncode": getattr(error, "returncode", None),
                    "stdout": bounded_output(error.stdout),
                    "stderr": bounded_output(error.stderr),
                })
            super().addError(test, err)

    try:
        report["metadata"] = metadata()
        # Fail admission before running if metadata cannot be recorded as JSON.
        json.dumps(report["metadata"])
        if report["selected_tests"] != 1:
            raise ValueError("exactly one test is required")
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Observer).run(suite)
        report.update(tests_run=result.testsRun, failures=len(result.failures),
                      errors=len(result.errors), skipped=len(result.skipped),
                      test_successful=result.wasSuccessful())
    except Exception as error:
        report["diagnostic_errors"].append(type(error).__name__ + ": " + str(error)[:OUTPUT_LIMIT])
        report["metadata"] = {}
    report["elapsed_seconds"] = round(time.monotonic() - started, 6)
    code = 0 if (report["test_successful"] is True and report["tests_run"] == 1
                 and report["skipped"] == 0 and not report["diagnostic_errors"]) else 1
    print("BOUNDARY_DIAGNOSTIC_JSON=" + json.dumps(report, sort_keys=True), file=stream, flush=True)
    return code, report


def admitted_metadata(subject, tools_commit):
    tools = Path(__file__).resolve().parents[1]
    identities = {}
    for label, root, expected in (("subject", subject, SUBJECT_COMMIT),
                                  ("tools", tools, tools_commit)):
        actual = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                capture_output=True, text=True, check=True, timeout=5).stdout.strip()
        dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                               capture_output=True, text=True, check=True, timeout=5).stdout
        if actual != expected or dirty:
            raise ValueError(label + " checkout identity or cleanliness mismatch")
        identities[label + "_commit"] = actual
    chrome = shutil.which("google-chrome-stable") or shutil.which("google-chrome")
    if not chrome:
        raise FileNotFoundError("Chrome is required")
    version = subprocess.run([chrome, "--version"], capture_output=True, text=True,
                             check=True, timeout=5).stdout.strip()
    if not version or len(version) > OUTPUT_LIMIT:
        raise ValueError("Chrome version is empty or exceeds output bound")
    return {**identities, "chrome_version": version, "test_name": TEST_NAME}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subject", type=Path, required=True)
    parser.add_argument("--tools-commit", required=True)
    args = parser.parse_args()
    subject = args.subject.resolve()
    # Admission precedes importing the subject; keep all product imports there.
    metadata = None
    admission_error = None
    try:
        metadata = admitted_metadata(subject, args.tools_commit)
    except Exception as error:
        admission_error = error
    if admission_error is None:
        os.chdir(subject)
        sys.path[:0] = [str(subject), str(subject / "src")]
        suite = unittest.defaultTestLoader.loadTestsFromName(TEST_NAME)
    else:
        suite = unittest.TestSuite()

    def admitted():
        if admission_error is not None:
            raise admission_error
        return metadata

    code, _ = run_diagnostic(suite, admitted)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
