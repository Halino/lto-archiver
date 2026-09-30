"""Exact approved MAM authority, including legacy parsing and durable binding."""

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ltobackup.broker.protocol import decode_request, encode_request
from ltobackup.qualification.broker_models import (
    qualification_request_authorization_payload,
    qualification_request_operation_token,
)
from ltobackup.qualification.plan import (
    QualificationOperation,
    QualificationPlan,
    QualificationRefused,
)
from tests.test_broker_ltfs_qualification import _open_store, request_model
from tests.test_ltfs_qualification_plan import make_plan

MAM = "V210531095"


def exact_plan():
    return make_plan(schema=2, expected_mam_medium_serial=MAM)


def exact_request(operation=QualificationOperation.FORMAT):
    original = request_model()
    plan = QualificationPlan(
        schema=2,
        run_id=original.run_id,
        job_id="job",
        cassette_sequence=1,
        physical_label=original.expected_physical_label,
        tape_serial=original.expected_tape_serial,
        drive_serial=original.expected_drive_serial,
        drive_wwid=original.expected_drive_wwid,
        linux_tree_sha256="a" * 64,
        ltfs_tree_sha256="b" * 64,
        ltfs_rpm_sha256="c" * 64,
        issued_at_ns=original.issued_at_ns,
        expires_at_ns=original.expires_at_ns,
        operations=(operation,),
        expected_mam_medium_serial=MAM,
    )
    unsigned = replace(
        original,
        protocol_version=2,
        operation=operation,
        plan_sha256=plan.plan_sha256,
        canonical_plan_json=plan.canonical_bytes().decode(),
        operation_token="0" * 64,
    )
    return replace(
        unsigned,
        operation_token=qualification_request_operation_token(unsigned, b"q" * 32),
    )


class ExactMediumTests(unittest.TestCase):
    def test_legacy_plan_request_and_readonly_token_match_original_release_bytes(self):
        plan = make_plan()
        self.assertEqual(
            plan.plan_sha256,
            "4ebc4a64eaaa73da67b35070873baae4590223bb2f2f36422707b9c0cbe7d9ee",
        )
        self.assertEqual(
            plan.authorize(QualificationOperation.READ_ONLY, b"q" * 32),
            "80e5cd892519f9e43d07f1e356667083d51ea48247bccb7612ba7b387802abf4",
        )
        self.assertEqual(
            request_model().request_sha256,
            "71076934926e98db371b1c9926aaa36341d0049d2229b9e6c21c6250b94efe2a",
        )

    def test_duplicate_plan_keys_are_rejected_instead_of_silently_rebinding_mam(self):
        raw = exact_plan().canonical_bytes()
        raw = raw.replace(
            b'"expected_mam_medium_serial":',
            b'"expected_mam_medium_serial":"OTHER","expected_mam_medium_serial":',
        )
        with self.assertRaises(QualificationRefused):
            QualificationPlan.from_bytes(raw)

    def test_rebound_serial_with_updated_digest_still_invalidates_original_request_token(
        self,
    ):
        from ltobackup.qualification.broker_executor import BrokerQualificationExecutor

        original = exact_request()
        plan = QualificationPlan.from_bytes(original.canonical_plan_json.encode())
        changed = replace(plan, expected_mam_medium_serial="OTHER")
        request = replace(
            original,
            plan_sha256=changed.plan_sha256,
            canonical_plan_json=changed.canonical_bytes().decode(),
        )
        self.assertNotEqual(request.request_sha256, original.request_sha256)

        def forbidden(request):
            self.fail("physical execution reached")

        driver = SimpleNamespace(
            **{
                operation.value: forbidden
                for operation in QualificationOperation
                if operation is not QualificationOperation.LONG_WIPE
            }
        )
        executor = BrokerQualificationExecutor(
            driver, credential=b"q" * 32, now_ns=lambda: request.issued_at_ns + 1
        )
        with self.assertRaisesRegex(QualificationRefused, "token"):
            executor.execute(request)

    def test_cli_exposes_explicit_mam_pin(self):
        from ltobackup.qualification.cli import _parser

        arguments = [
            "plan",
            "--catalog",
            "/catalog",
            "--job-id",
            "job",
            "--cassette-sequence",
            "1",
            "--expected-label",
            "LABEL",
            "--drive-serial",
            "DRIVE",
            "--drive-wwid",
            "WWID",
            "--linux-tree-sha256",
            "a" * 64,
            "--ltfs-tree-sha256",
            "b" * 64,
            "--ltfs-rpm-sha256",
            "c" * 64,
            "--operation",
            "format",
            "--expected-mam-medium-serial",
            MAM,
        ]
        self.assertEqual(
            _parser().parse_args(arguments).expected_mam_medium_serial, MAM
        )

    def test_service_rejects_unpinned_format_before_any_store_mutation(self):
        from ltobackup.broker.service import CommandBrokerService

        request = replace(request_model(), operation=QualificationOperation.FORMAT)
        service = object.__new__(CommandBrokerService)
        service._qualification_executor = object()
        service.store = SimpleNamespace(
            prepare_ltfs_qualification=lambda request: self.fail("store was mutated")
        )
        with self.assertRaises(QualificationRefused):
            service._execute_ltfs_qualification_stage({"request": request})

    def test_physical_runtime_rejects_unpinned_format_before_probe_or_workspace(self):
        from ltobackup.qualification.physical_runtime import (
            SystemPhysicalLtfsQualificationRuntime,
        )

        runtime = object.__new__(SystemPhysicalLtfsQualificationRuntime)
        request = replace(request_model(), operation=QualificationOperation.FORMAT)
        with (
            patch.object(
                runtime,
                "_probe",
                side_effect=lambda *a, **kw: self.fail("probe reached"),
            ),
            self.assertRaises(QualificationRefused),
        ):
            runtime.execute(QualificationOperation.FORMAT, request)

    def test_schema_two_serial_is_closed_and_changes_plan_authorization(self):
        plan = exact_plan()
        self.assertEqual(QualificationPlan.from_bytes(plan.canonical_bytes()), plan)
        self.assertEqual(
            json.loads(plan.canonical_bytes())["expected_mam_medium_serial"], MAM
        )
        token = plan.authorize(QualificationOperation.FORMAT, b"q" * 32)
        with self.assertRaises(QualificationRefused):
            replace(plan, expected_mam_medium_serial="OTHER").verify_token(
                QualificationOperation.FORMAT,
                token,
                b"q" * 32,
                now_ns=plan.issued_at_ns + 1,
            )
        for serial in (None, "", " V210531095", "V210531095 ", "a\n", "é", "a" * 256):
            with self.assertRaises(QualificationRefused):
                replace(plan, expected_mam_medium_serial=serial)

    def test_legacy_format_parses_but_cannot_obtain_new_authorization(self):
        plan = make_plan()
        raw = plan.canonical_bytes()
        self.assertEqual(QualificationPlan.from_bytes(raw).canonical_bytes(), raw)
        self.assertNotIn(b"expected_mam_medium_serial", raw)
        with self.assertRaisesRegex(QualificationRefused, "MAM"):
            plan.authorize(QualificationOperation.FORMAT, b"q" * 32)
        self.assertEqual(
            len(plan.authorize(QualificationOperation.READ_ONLY, b"q" * 32)), 64
        )

    def test_request_embeds_authenticates_and_cross_validates_canonical_plan(self):
        request = exact_request()
        packet = encode_request(
            "execute_ltfs_qualification_stage",
            params={"request": request},
            capability=b"c" * 32,
            request_id=b"i" * 32,
        )
        decoded = decode_request(packet).params["request"]
        self.assertEqual(decoded, request)
        self.assertIn(
            MAM.encode(), qualification_request_authorization_payload(request)
        )
        for mutation in (
            {"canonical_plan_json": None},
            {"canonical_plan_json": request.canonical_plan_json + "\n"},
            {"plan_sha256": "0" * 64},
            {"expected_physical_label": "OTHER"},
            {"operation": QualificationOperation.WIPE},
            {"expires_at_ns": request.expires_at_ns + 1},
        ):
            with self.assertRaises(QualificationRefused):
                replace(request, **mutation)

    def test_broker_sqlite_reopen_retains_serial_bound_request_digest(self):
        request = exact_request()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broker.db"
            store = _open_store(path)
            stage = store.prepare_ltfs_qualification(request).record
            self.assertEqual(stage.request_sha256, request.request_sha256)
            self.assertEqual(
                stage.plan_sha256,
                hashlib.sha256(request.canonical_plan_json.encode()).hexdigest(),
            )
            store.close()
            reopened = _open_store(path)
            try:
                actual = reopened.ltfs_qualification_stage(
                    request.run_id, request.stage_ordinal
                )
                self.assertEqual(actual.request_sha256, request.request_sha256)
                self.assertEqual(actual.plan_sha256, request.plan_sha256)
            finally:
                reopened.close()
