import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ltobackup.catalog import Catalog
from ltobackup.errors import CatalogError
from ltobackup.qualification.plan import QualificationOperation, QualificationPlan
from ltobackup.qualification.runner import (
    QualificationExecution,
    QualificationFenced,
    QualificationObservation,
    QualificationRunner,
)

NOW = 1_787_500_000_000_000_000
CREDENTIAL = b"qualification-test-credential!".ljust(32, b"!")
SUPPORTED_OPERATIONS = (
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


def all_operations_plan(**overrides) -> QualificationPlan:
    fields = {
        "schema": 2,
        "expected_mam_medium_serial": "CURRENT-SERIAL",
        "run_id": "11111111-1111-4111-8111-111111111111",
        "job_id": "JOB1",
        "cassette_sequence": 4,
        "physical_label": r"CURRENT/LABEL\EXACT",
        "tape_serial": "CURRENT-SERIAL",
        "drive_serial": "DRIVE-SERIAL",
        "drive_wwid": "0x5000000000000001",
        "linux_tree_sha256": "a" * 64,
        "ltfs_tree_sha256": "b" * 64,
        "ltfs_rpm_sha256": "c" * 64,
        "issued_at_ns": NOW,
        "expires_at_ns": NOW + 3_600_000_000_000,
        "operations": SUPPORTED_OPERATIONS,
    }
    fields.update(overrides)
    return QualificationPlan(**fields)


def observation(**overrides) -> QualificationObservation:
    fields = {
        "physical_label": r"CURRENT/LABEL\EXACT",
        "tape_serial": "CURRENT-SERIAL",
        "drive_serial": "DRIVE-SERIAL",
        "drive_wwid": "0x5000000000000001",
        "volume_uuid": "22222222-2222-4222-8222-222222222222",
        "index_generation": 7,
    }
    fields.update(overrides)
    return QualificationObservation(**fields)


class RecordingExecutor:
    def __init__(self, observations=None, failure_at=None, exit_codes=None):
        self.observations = list(observations or [observation()] * 64)
        self.failure_at = failure_at
        self.exit_codes = dict(exit_codes or {})
        self.executed = []

    def observe(self):
        if not self.observations:
            raise AssertionError("observation fixture exhausted")
        return self.observations.pop(0)

    def execute(self, operation, *, plan, request_sha256):
        self.executed.append((operation, plan.physical_label, request_sha256))
        if operation is self.failure_at:
            raise RuntimeError("synthetic ambiguous device response")
        return QualificationExecution(
            terminal_receipt_sha256=operation.value[0].encode().hex().ljust(64, "0"),
            child_exit_code=self.exit_codes.get(
                operation,
                1 if operation is QualificationOperation.WIPE else 0,
            ),
            content_manifest_sha256=(
                "d" * 64
                if operation
                in {
                    QualificationOperation.READ_ONLY,
                    QualificationOperation.ADDITIVE_WRITE,
                    QualificationOperation.OVERWRITE,
                    QualificationOperation.REPAIR,
                }
                else None
            ),
        )


class QualificationRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        source = root / "source"
        source.mkdir()
        self.catalog = Catalog(root / "catalog.sqlite3")
        self.addCleanup(self.catalog.close)
        self.catalog.initialize()
        self.catalog.add_library("LIB1", "Library", str(source))
        self.catalog.create_automatic_job(
            "JOB1",
            "LIB1",
            "drive",
            "/synthetic/mount",
            [
                ("LABEL1", "SERIAL1", 0, 0),
                ("LABEL2", "SERIAL2", 0, 0),
                ("LABEL3", "SERIAL3", 0, 0),
                (r"CURRENT/LABEL\EXACT", "CURRENT-SERIAL", 0, 0),
            ],
            force_format=True,
        )

    def runner(self, plan, executor):
        return QualificationRunner(
            catalog=self.catalog,
            plan=plan,
            credential=CREDENTIAL,
            executor=executor,
            now_ns=lambda: NOW,
        )

    def test_every_supported_ltfs_operation_is_dispatched_once_with_durable_evidence(self):
        plan = all_operations_plan()
        executor = RecordingExecutor()
        tokens = {
            operation: plan.authorize(operation, CREDENTIAL)
            for operation in plan.operations
        }

        self.runner(plan, executor).run(tokens)

        expected_order = (
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
        self.assertEqual(expected_order, tuple(item[0] for item in executor.executed))
        self.assertTrue(
            all(item[1] == r"CURRENT/LABEL\EXACT" for item in executor.executed)
        )
        stages = self.catalog.connection.execute(
            "SELECT ordinal,operation,dispatched,verdict,child_exit_code "
            "FROM ltfs_qualification_stages ORDER BY ordinal"
        ).fetchall()
        self.assertEqual(18, len(stages))
        self.assertEqual(
            tuple(
                (operation.value, "dispatch_started") for operation in expected_order
            ),
            tuple((stages[index][1], stages[index][3]) for index in range(0, 18, 2)),
        )
        self.assertEqual(
            tuple((operation.value, "pass") for operation in expected_order),
            tuple((stages[index][1], stages[index][3]) for index in range(1, 18, 2)),
        )
        self.assertEqual(
            "completed",
            self.catalog.connection.execute(
                "SELECT status FROM ltfs_qualification_runs WHERE run_id=?",
                (plan.run_id,),
            ).fetchone()[0],
        )

    def test_legacy_long_wipe_plan_is_rejected_before_executor_dispatch(self):
        plan = all_operations_plan(operations=(QualificationOperation.WIPE,))
        object.__setattr__(
            plan, "operations", (QualificationOperation.LONG_WIPE,)
        )
        executor = RecordingExecutor()
        with (
            patch.object(QualificationPlan, "verify_token", return_value=None),
            self.assertRaisesRegex(ValueError, "unsupported"),
        ):
            self.runner(plan, executor).run(
                {QualificationOperation.LONG_WIPE: "0" * 64}
            )
        self.assertEqual([], executor.executed)

    def test_label_serial_or_drive_substitution_fences_before_dispatch(self):
        plan = all_operations_plan(operations=(QualificationOperation.FORMAT,))
        for field, value in (
            ("physical_label", "CURRENT/LABEL/OTHER"),
            ("tape_serial", "current-serial"),
            ("drive_serial", "OTHER-DRIVE"),
            ("drive_wwid", "0x5000000000000002"),
        ):
            with self.subTest(field=field):
                isolated_plan = replace(
                    plan,
                    run_id={
                        "physical_label": "21111111-1111-4111-8111-111111111111",
                        "tape_serial": "31111111-1111-4111-8111-111111111111",
                        "drive_serial": "41111111-1111-4111-8111-111111111111",
                        "drive_wwid": "51111111-1111-4111-8111-111111111111",
                    }[field],
                )
                executor = RecordingExecutor(
                    observations=[replace(observation(), **{field: value})]
                )
                token = isolated_plan.authorize(
                    QualificationOperation.FORMAT, CREDENTIAL
                )
                with self.assertRaises(QualificationFenced):
                    self.runner(isolated_plan, executor).run(
                        {QualificationOperation.FORMAT: token}
                    )
                self.assertEqual([], executor.executed)
                status = self.catalog.connection.execute(
                    "SELECT status FROM ltfs_qualification_runs WHERE run_id=?",
                    (isolated_plan.run_id,),
                ).fetchone()[0]
                self.assertEqual("fenced", status)

    def test_ambiguous_destructive_dispatch_is_not_retried(self):
        plan = all_operations_plan(operations=(QualificationOperation.WIPE,))
        executor = RecordingExecutor(failure_at=QualificationOperation.WIPE)
        token = plan.authorize(QualificationOperation.WIPE, CREDENTIAL)

        with self.assertRaises(QualificationFenced):
            self.runner(plan, executor).run({QualificationOperation.WIPE: token})
        with self.assertRaises(CatalogError):
            self.runner(plan, executor).run({QualificationOperation.WIPE: token})

        self.assertEqual(1, len(executor.executed))
        evidence = self.catalog.connection.execute(
            "SELECT dispatched,verdict FROM ltfs_qualification_stages ORDER BY ordinal"
        ).fetchall()
        self.assertEqual([(1, "dispatch_started")], [tuple(row) for row in evidence])

    def test_repair_one_is_success_but_wipe_zero_is_fenced(self):
        repair_plan = all_operations_plan(
            run_id="61111111-1111-4111-8111-111111111111",
            operations=(QualificationOperation.REPAIR,),
        )
        repair = RecordingExecutor(exit_codes={QualificationOperation.REPAIR: 1})
        self.runner(repair_plan, repair).run(
            {
                QualificationOperation.REPAIR: repair_plan.authorize(
                    QualificationOperation.REPAIR, CREDENTIAL
                )
            }
        )
        self.assertEqual(
            "completed",
            self.catalog.connection.execute(
                "SELECT status FROM ltfs_qualification_runs WHERE run_id=?",
                (repair_plan.run_id,),
            ).fetchone()[0],
        )

        wipe_plan = all_operations_plan(
            run_id="71111111-1111-4111-8111-111111111111",
            operations=(QualificationOperation.WIPE,),
        )
        wipe = RecordingExecutor(exit_codes={QualificationOperation.WIPE: 0})
        with self.assertRaises(QualificationFenced):
            self.runner(wipe_plan, wipe).run(
                {
                    QualificationOperation.WIPE: wipe_plan.authorize(
                        QualificationOperation.WIPE, CREDENTIAL
                    )
                }
            )
        self.assertEqual(1, len(wipe.executed))

    def test_post_operation_label_substitution_fences_terminal_result(self):
        plan = all_operations_plan(operations=(QualificationOperation.FORMAT,))
        executor = RecordingExecutor(
            observations=[
                observation(),
                observation(physical_label="SUBSTITUTED"),
            ]
        )
        token = plan.authorize(QualificationOperation.FORMAT, CREDENTIAL)

        with self.assertRaises(QualificationFenced):
            self.runner(plan, executor).run({QualificationOperation.FORMAT: token})

        self.assertEqual(1, len(executor.executed))
        self.assertEqual(
            "fenced",
            self.catalog.connection.execute(
                "SELECT status FROM ltfs_qualification_runs WHERE run_id=?",
                (plan.run_id,),
            ).fetchone()[0],
        )


if __name__ == "__main__":
    unittest.main()
