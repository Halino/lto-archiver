"""Pre-install failures retain safe diagnostics and resume only bound sources."""

from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest import mock

from tests import test_rhel9_deployment as fixtures


class PredecessorFailureTests(unittest.TestCase):
    setUp = fixtures.Rhel9DeploymentTests.setUp
    tearDown = fixtures.Rhel9DeploymentTests.tearDown

    def recovery_host(self, *, source_valid=True, gate_failure=None):
        catalog = self.root / "stopped-catalog"
        catalog.write_bytes(b"stopped predecessor")
        prepared = catalog.read_bytes()
        state = SimpleNamespace(started=False)

        def validate_source(selected):
            return source_valid and selected == catalog.read_bytes()

        def activate(_manifest):
            state.started = True
            catalog.write_bytes(b"healthy predecessor after housekeeping")

        host = object.__new__(self.module.SystemDeploymentHost)
        host._rollback_host = SimpleNamespace(
            _pre_mask_enablement={"lto-archiverd.service": "enabled"},
            validate_prepared_source=validate_source,
            activate_old_stack=activate,
            all_units_active=lambda units: (
                state.started and units == self.module.STOP_UNITS
                and gate_failure != "units"
            ),
        )
        host.validate_predecessor_source = lambda _request: (
            state.started and gate_failure != "source"
        )
        host.observe_admission = lambda _request: replace(
            self.host.admission,
            daemon_reconciled=state.started and gate_failure != "admission",
        )
        return host, prepared, state

    def test_resume_accepts_normal_catalog_housekeeping_after_activation(self):
        host, prepared, state = self.recovery_host()
        self.assertTrue(host.resume_unchanged_predecessor(self.request, prepared))
        self.assertTrue(state.started)

    def test_invalid_stopped_source_never_starts_predecessor(self):
        host, prepared, state = self.recovery_host(source_valid=False)
        self.assertFalse(host.resume_unchanged_predecessor(self.request, prepared))
        self.assertFalse(state.started)

    def test_stopped_source_validation_exception_never_starts_predecessor(self):
        host, prepared, state = self.recovery_host()
        with mock.patch.object(
            host._rollback_host, "validate_prepared_source",
            side_effect=OSError("private /recovery/path"),
        ):
            self.assertFalse(host.resume_unchanged_predecessor(self.request, prepared))
        self.assertFalse(state.started)

    def test_resume_still_requires_every_post_activation_gate(self):
        for gate in ("source", "units", "admission"):
            with self.subTest(gate=gate):
                host, prepared, state = self.recovery_host(gate_failure=gate)
                self.assertFalse(host.resume_unchanged_predecessor(self.request, prepared))
                self.assertTrue(state.started)

    def test_blocked_bundle_failure_keeps_phase_and_cause_without_exception_text(self):
        class RollbackError(RuntimeError):
            pass

        def failed_bundle(*_args):
            try:
                raise MemoryError("private /catalog/path and credentials")
            except MemoryError as error:
                raise RollbackError("private /bundle/path") from error

        self.host.resume_ok = False
        with mock.patch.object(self.host, "create_verified_rollback", failed_bundle):
            result = self.module.deploy(self.request, self.host)
        self.assertEqual("blocked", result.status)
        self.assertIn("phase=create_rollback", result.detail)
        self.assertIn("error=RollbackError", result.detail)
        self.assertIn("cause=MemoryError", result.detail)
        self.assertNotIn("private", result.detail)
        self.assertNotIn("/", result.detail)
        self.assertLessEqual(len(result.detail), 192)
        self.assertTrue(self.host.masks_kept)

    def test_blocked_preparation_and_registration_failures_have_distinct_phases(self):
        for failure, phase in (
            ("prepare-recovery", "prepare_source"),
            ("artifact-registration", "register_rollback"),
        ):
            with self.subTest(failure=failure):
                host = fixtures.FakeDeploymentHost(self.module, self.root)
                host.fail_at = failure
                host.resume_ok = False
                result = self.module.deploy(self.request, host)
                self.assertEqual("blocked", result.status)
                self.assertIn(f"phase={phase}", result.detail)
                self.assertIn("error=RuntimeError", result.detail)
                self.assertNotIn("injected", result.detail)

    def test_blocked_diagnostics_bound_unusual_exception_class_names(self):
        unsafe_error = type("private/path\n" + "x" * 300, (Exception,), {})
        self.host.resume_ok = False
        with mock.patch.object(
            self.host, "create_verified_rollback", side_effect=unsafe_error("secret"),
        ):
            result = self.module.deploy(self.request, self.host)
        self.assertEqual("blocked", result.status)
        self.assertIn("phase=create_rollback", result.detail)
        self.assertIn("error=Exception", result.detail)
        self.assertNotIn("private", result.detail)
        self.assertNotIn("secret", result.detail)
        self.assertLessEqual(len(result.detail), 192)
