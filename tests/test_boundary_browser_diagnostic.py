"""Behavioral checks of the passive diagnostic observer, without Chrome."""

import base64
import io
import json
import runpy
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


HELPER = Path(__file__).resolve().parents[1] / "scripts" / "observe-boundary-browser.py"


class BoundaryBrowserDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HELPER.is_file(), "diagnostic helper is absent")
        self.helper = runpy.run_path(str(HELPER))

    def observe(self, body, *, metadata=None):
        case = unittest.FunctionTestCase(body)
        stream = io.StringIO()
        code, report = self.helper["run_diagnostic"](
            unittest.TestSuite([case]), metadata or (lambda: {"chrome_version": "known-version"}),
            stream=stream,
        )
        serialized = stream.getvalue().split("BOUNDARY_DIAGNOSTIC_JSON=", 1)[1]
        self.assertEqual(json.loads(serialized), report)
        self.assertGreaterEqual(report["elapsed_seconds"], 0)
        return code, report

    def test_success_preserves_count_and_metadata(self):
        code, report = self.observe(lambda: None)
        self.assertEqual(code, 0)
        self.assertEqual(report["tests_run"], 1)
        self.assertTrue(report["test_successful"])
        self.assertEqual(report["metadata"]["chrome_version"], "known-version")

    def test_failure_and_error_remain_nonzero(self):
        for exception, field in [(AssertionError("known failure"), "failures"),
                                 (RuntimeError("known error"), "errors")]:
            with self.subTest(field=field):
                def body():
                    raise exception
                code, report = self.observe(body)
                self.assertEqual(code, 1)
                self.assertEqual(report[field], 1)
                self.assertFalse(report["test_successful"])

    def test_skip_is_rejected_even_when_unittest_successful(self):
        def body():
            raise unittest.SkipTest("known skip")
        code, report = self.observe(body)
        self.assertEqual(code, 1)
        self.assertEqual(report["skipped"], 1)
        self.assertTrue(report["test_successful"])

    def test_zero_and_multiple_tests_are_rejected_before_execution(self):
        for count in (0, 2):
            with self.subTest(count=count):
                executed = []
                suite = unittest.TestSuite([
                    unittest.FunctionTestCase(lambda: executed.append(True)) for _ in range(count)
                ])
                code, report = self.helper["run_diagnostic"](
                    suite, lambda: {}, stream=io.StringIO(),
                )
                self.assertEqual(code, 1)
                self.assertEqual(report["selected_tests"], count)
                self.assertEqual(report["tests_run"], 0)
                self.assertEqual(executed, [])

    def test_real_timeout_retains_partial_output_for_both_subprocess_modes(self):
        for text in (False, True):
            with self.subTest(text=text):
                def body():
                    subprocess.run([
                        sys.executable, "-c",
                        "import sys,time; print('known-out',flush=True); "
                        "print('known-err',file=sys.stderr,flush=True); time.sleep(5)",
                    ], capture_output=True, text=text, timeout=0.3, check=True)
                code, report = self.observe(body)
                self.assertEqual(code, 1)
                self.assertEqual(report["errors"], 1)
                error = report["process_errors"][0]
                self.assertEqual(error["exception"], "TimeoutExpired")
                self.assertEqual(error["timeout"], 0.3)
                self.assertEqual(base64.b64decode(error["stdout"]["prefix_base64"]), b"known-out\n")
                self.assertEqual(base64.b64decode(error["stderr"]["prefix_base64"]), b"known-err\n")

    def test_real_nonzero_subprocess_retains_text_output_and_returncode(self):
        def body():
            subprocess.run([
                sys.executable, "-c",
                "import sys; print('failed-out'); print('failed-err',file=sys.stderr); sys.exit(7)",
            ], capture_output=True, text=True, check=True)
        code, report = self.observe(body)
        self.assertEqual(code, 1)
        error = report["process_errors"][0]
        self.assertEqual(error["returncode"], 7)
        self.assertEqual(error["stdout"]["prefix"], "failed-out\n")
        self.assertEqual(error["stderr"]["prefix"], "failed-err\n")

    def test_byte_and_text_reports_bound_output_without_losing_length(self):
        for value in (b"x" * 10000, "é" * 10000):
            with self.subTest(type=type(value).__name__):
                def body():
                    raise subprocess.TimeoutExpired("probe", 30, output=value, stderr=value)
                code, report = self.observe(body)
                self.assertEqual(code, 1)
                output = report["process_errors"][0]["stdout"]
                self.assertEqual(output["length"], 10000)
                prefix = (base64.b64decode(output["prefix_base64"])
                          if isinstance(value, bytes) else output["prefix"])
                self.assertEqual(len(prefix), 8192)
                self.assertEqual(prefix, value[:8192])

    def test_metadata_failure_is_reported_and_prevents_probe(self):
        for exception in (FileNotFoundError("Chrome missing"), RuntimeError("identity mismatch")):
            with self.subTest(exception=type(exception).__name__):
                executed = []
                def metadata():
                    raise exception
                code, report = self.observe(lambda: executed.append(True), metadata=metadata)
                self.assertEqual(code, 1)
                self.assertEqual(report["tests_run"], 0)
                self.assertIn(type(exception).__name__, report["diagnostic_errors"][0])
                self.assertEqual(executed, [])

    def test_unrecordable_metadata_prevents_probe_and_still_emits_json(self):
        executed = []
        code, report = self.observe(lambda: executed.append(True), metadata=lambda: {"bad": object()})
        self.assertEqual(code, 1)
        self.assertEqual(report["tests_run"], 0)
        self.assertEqual(report["metadata"], {})
        self.assertIn("TypeError", report["diagnostic_errors"][0])
        self.assertEqual(executed, [])

    def test_admission_rejects_checkout_mismatch_or_missing_chrome(self):
        def git_response(argv, **kwargs):
            output = ("4507cd23e96fef48dd3099d0da69bb7cda3a9a27\n"
                      if argv[-1] == "HEAD" else "")
            return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")
        with patch("subprocess.run", side_effect=git_response), patch("shutil.which", return_value=None):
            with self.assertRaisesRegex(ValueError, "tools checkout identity"):
                self.helper["admitted_metadata"](Path("unused"), "different-commit")
            with self.assertRaisesRegex(FileNotFoundError, "Chrome is required"):
                self.helper["admitted_metadata"](
                    Path("unused"), "4507cd23e96fef48dd3099d0da69bb7cda3a9a27",
                )

    def test_cli_unadmitted_subject_reports_zero_tests_without_importing_subject(self):
        # A nonexistent subject is rejected by git before any Chrome lookup.
        result = subprocess.run([
            sys.executable, str(HELPER), "--subject", str(HELPER / "absent"),
            "--tools-commit", "4507cd23e96fef48dd3099d0da69bb7cda3a9a27",
        ], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout.split("BOUNDARY_DIAGNOSTIC_JSON=", 1)[1])
        self.assertEqual(report["selected_tests"], 0)
        self.assertEqual(report["tests_run"], 0)
        self.assertIn("CalledProcessError", report["diagnostic_errors"][0])


if __name__ == "__main__":
    unittest.main()
