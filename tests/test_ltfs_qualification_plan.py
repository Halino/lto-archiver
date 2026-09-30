import json
import unittest
from dataclasses import replace

from ltobackup.qualification.plan import (
    QualificationOperation,
    QualificationPlan,
    QualificationRefused,
    qualification_success_exit_codes,
)

NOW = 1_787_500_000_000_000_000
RUN_ID = "11111111-1111-4111-8111-111111111111"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def make_plan(**overrides):
    fields = {
        "schema": 1,
        "run_id": RUN_ID,
        "job_id": "job-qualification",
        "cassette_sequence": 4,
        "physical_label": "CURRENT/TAPE\\LABEL",
        "tape_serial": "SERIAL-0004",
        "drive_serial": "DRIVE-TEST",
        "drive_wwid": "0x5000000000000001",
        "linux_tree_sha256": SHA_A,
        "ltfs_tree_sha256": SHA_B,
        "ltfs_rpm_sha256": SHA_C,
        "issued_at_ns": NOW,
        "expires_at_ns": NOW + 3_600_000_000_000,
        "operations": (
            QualificationOperation.READ_ONLY,
            QualificationOperation.FORMAT,
            QualificationOperation.WIPE,
        ),
    }
    fields.update(overrides)
    return QualificationPlan(**fields)


class QualificationPlanTests(unittest.TestCase):
    def test_canonical_plan_preserves_exact_label_and_has_closed_schema(self):
        plan = make_plan()
        payload = json.loads(plan.canonical_bytes())
        self.assertEqual("CURRENT/TAPE\\LABEL", payload["physical_label"])
        self.assertEqual(["format", "read_only", "wipe"], payload["operations"])
        self.assertEqual(plan.plan_sha256, plan.plan_sha256)
        self.assertEqual(64, len(plan.plan_sha256))
        self.assertEqual(plan, QualificationPlan.from_bytes(plan.canonical_bytes()))

    def test_token_is_bound_to_exact_label_operation_and_run(self):
        plan = make_plan(schema=2, expected_mam_medium_serial="APPROVED-MAM")
        credential = b"k" * 32
        token = plan.authorize(QualificationOperation.FORMAT, credential)
        plan.verify_token(
            QualificationOperation.FORMAT, token, credential, now_ns=NOW + 1
        )
        for mutation in (
            replace(plan, physical_label="current/TAPE\\LABEL"),
            replace(plan, tape_serial="SERIAL-OTHER"),
            replace(plan, run_id="22222222-2222-4222-8222-222222222222"),
            replace(plan, ltfs_rpm_sha256="d" * 64),
        ):
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(QualificationRefused),
            ):
                mutation.verify_token(
                    QualificationOperation.FORMAT,
                    token,
                    credential,
                    now_ns=NOW + 1,
                )
        with self.assertRaises(QualificationRefused):
            plan.verify_token(
                QualificationOperation.WIPE, token, credential, now_ns=NOW + 1
            )

    def test_expired_unknown_and_unplanned_operations_are_rejected(self):
        plan = make_plan(schema=2, expected_mam_medium_serial="APPROVED-MAM")
        credential = b"z" * 32
        token = plan.authorize(QualificationOperation.FORMAT, credential)
        with self.assertRaisesRegex(QualificationRefused, "expired"):
            plan.verify_token(
                QualificationOperation.FORMAT,
                token,
                credential,
                now_ns=plan.expires_at_ns + 1,
            )
        with self.assertRaisesRegex(QualificationRefused, "not planned"):
            plan.authorize(QualificationOperation.EJECT, credential)
        with self.assertRaises(QualificationRefused):
            plan.verify_token(
                QualificationOperation.FORMAT,
                "0" * 64,
                credential,
                now_ns=NOW + 1,
            )

    def test_from_catalog_preserves_db_label_and_rejects_case_substitution(self):
        plan = QualificationPlan.from_catalog(
            {
                "job_id": "job-qualification",
                "sequence": 4,
                "physical_label": "ExactLabel",
                "tape_serial": "ExactSerial",
            },
            run_id=RUN_ID,
            drive_serial="DRIVE-TEST",
            drive_wwid="0x5000000000000001",
            linux_tree_sha256=SHA_A,
            ltfs_tree_sha256=SHA_B,
            ltfs_rpm_sha256=SHA_C,
            issued_at_ns=NOW,
            expires_at_ns=NOW + 1_000_000_000,
            operations=(QualificationOperation.READ_ONLY,),
        )
        self.assertEqual("ExactLabel", plan.physical_label)
        self.assertEqual("ExactSerial", plan.tape_serial)
        with self.assertRaises(QualificationRefused):
            QualificationPlan.from_catalog(
                {
                    "job_id": "job-qualification",
                    "sequence": 4,
                    "physical_label": "exactlabel",
                    "tape_serial": "ExactSerial",
                },
                expected_physical_label="ExactLabel",
                run_id=RUN_ID,
                drive_serial="DRIVE-TEST",
                drive_wwid="0x5000000000000001",
                linux_tree_sha256=SHA_A,
                ltfs_tree_sha256=SHA_B,
                ltfs_rpm_sha256=SHA_C,
                issued_at_ns=NOW,
                expires_at_ns=NOW + 1_000_000_000,
                operations=(QualificationOperation.READ_ONLY,),
            )

    def test_closed_parser_rejects_extra_missing_and_malformed_fields(self):
        payload = json.loads(make_plan().canonical_bytes())
        mutations = []
        extra = dict(payload)
        extra["extra"] = True
        mutations.append(extra)
        missing = dict(payload)
        del missing["physical_label"]
        mutations.append(missing)
        malformed = dict(payload)
        malformed["run_id"] = "not-a-uuid"
        mutations.append(malformed)
        duplicate = dict(payload)
        duplicate["operations"] = ["format", "format"]
        mutations.append(duplicate)
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(QualificationRefused),
            ):
                QualificationPlan.from_bytes(
                    json.dumps(mutation, separators=(",", ":")).encode("utf-8")
                )

    def test_long_wipe_is_recognized_only_to_reject_historical_authority(self):
        with self.assertRaisesRegex(QualificationRefused, "unsupported"):
            make_plan(operations=(QualificationOperation.LONG_WIPE,))

        payload = json.loads(make_plan().canonical_bytes())
        payload["operations"] = ["long_wipe"]
        with self.assertRaisesRegex(QualificationRefused, "unsupported"):
            QualificationPlan.from_bytes(
                json.dumps(payload, separators=(",", ":")).encode("utf-8")
            )

        with self.assertRaisesRegex(QualificationRefused, "unsupported"):
            qualification_success_exit_codes(QualificationOperation.LONG_WIPE)


if __name__ == "__main__":
    unittest.main()
