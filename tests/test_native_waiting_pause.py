from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ltobackup.catalog import Catalog
from ltobackup.daemon.models import (
    CommandQuiescenceRequired, HardwareTargetBinding, OperationFence,
    OperationRecord, StaleOperationFence,
)
from ltobackup.daemon.native_runtime import _LinuxAutomaticController
from ltobackup.errors import ValidationError
from ltobackup.tape.linux_ltfs import LinuxLtfsBackend, MediaIdentityError
from ltobackup.tape.models import ExpectedMedia


class WaitingMediaPauseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.catalog = Catalog(root / "catalog.db")
        self.addCleanup(self.catalog.close)
        self.catalog.initialize()
        source = root / "source"
        source.mkdir()
        self.catalog.add_library("LIB", "Library", str(source))
        self.catalog.create_automatic_job(
            "NATIVE-JOB", "LIB", "drive", str(root / "mount"),
            [("TAPE07", "TAPE07", 1, 1)], force_format=True,
        )
        self.expected = ExpectedMedia(
            "archive.native", "NATIVE-JOB", 1, "TAPE07", None, None
        )
        owner = self.catalog.claim_daemon_owner("daemon-pause")
        self.record = OperationRecord(
            "operation-pause", "archive.native", "running", None,
            "pause-wait-fixture", "operator", "NATIVE-JOB", 1,
            "2026-09-05T07:00:00+00:00", None,
        )
        self.catalog.admit_operation(
            self.record, owner, admission_open=True,
            hardware_target=HardwareTargetBinding.from_verified_inputs(
                root / "mount", "tape-by-id", "scsi-by-id",
                ("archive.native", "NATIVE-JOB", "1", "TAPE07", "", ""),
            ),
            format_confirmation_label="TAPE07",
        )
        self.fence = OperationFence(self.record.id, owner.generation)
        self.catalog.update_automatic_job("NATIVE-JOB", "waiting_media", current_sequence=1)

    def acknowledge(self, checkpoint: str) -> bool:
        return self.catalog.acknowledge_job_pause(
            "NATIVE-JOB", checkpoint, fence=self.fence
        )

    def controller(self, backend) -> _LinuxAutomaticController:
        return _LinuxAutomaticController(
            backend, self.expected,
            SimpleNamespace(record=self.record, fence=self.fence),
            safe_checkpoint=self.acknowledge,
        )

    def test_pause_interrupts_real_backend_poll_before_media_arrives(self) -> None:
        for operation in ("format", "append"):
            with self.subTest(operation=operation):
                self.catalog.clear_job_pause("NATIVE-JOB", "operator")
                self.catalog.connection.execute(
                    "UPDATE automatic_cassettes SET operation=? WHERE job_id=?",
                    (operation, "NATIVE-JOB"),
                )
                self.catalog.connection.commit()
                calls: list[str] = []

                def missing_media():
                    calls.append("identify")
                    if len(calls) > 1:
                        raise AssertionError("media polling continued after pause request")
                    raise MediaIdentityError()

                backend = SimpleNamespace(
                    catalog=self.catalog, expected=self.expected,
                    monotonic=lambda: 0, media_wait_timeout=30, media_poll_seconds=1,
                    identify=missing_media, identify_preformat=missing_media,
                    sleep=lambda _seconds: self.catalog.request_job_pause("NATIVE-JOB", "operator"),
                )
                backend.wait_for_media = lambda expected, stop: LinuxLtfsBackend.wait_for_media(backend, expected, stop)
                backend.wait_for_preformat_media = lambda expected, stop: LinuxLtfsBackend.wait_for_preformat_media(backend, expected, stop)
                controller = self.controller(backend)
                self.assertFalse(controller.wait_for_media(lambda: False))
                self.assertTrue(controller.pause_acknowledged)
                state = self.catalog.job_management_state("NATIVE-JOB")
                self.assertIsNotNone(state["pause_acknowledged_at"])
                self.assertEqual("waiting_media", state["current_checkpoint"])
                self.assertEqual(["identify"], calls)
                self.assertFalse(controller._media_admitted)
                self.assertIsNone(controller._mounted)

    def test_waiting_pause_refuses_nonquiescent_command(self) -> None:
        self.catalog.request_job_pause("NATIVE-JOB", "operator")
        self.catalog.reserve_hardware_command(self.fence, "reserved-probe", "probe_media", "a" * 64)
        with self.assertRaises(CommandQuiescenceRequired):
            self.acknowledge("waiting_media")
        self.assertIsNone(self.catalog.job_management_state("NATIVE-JOB")["pause_acknowledged_at"])
        self.assertEqual("running", self.catalog.get_operation(self.record.id)["state"])

    def test_waiting_pause_refuses_stale_owner(self) -> None:
        self.catalog.request_job_pause("NATIVE-JOB", "operator")
        self.catalog.claim_daemon_owner("successor")
        with self.assertRaises(StaleOperationFence):
            self.acknowledge("waiting_media")
        self.assertIsNone(self.catalog.job_management_state("NATIVE-JOB")["pause_acknowledged_at"])

    def test_waiting_pause_refuses_writing_phase(self) -> None:
        self.catalog.request_job_pause("NATIVE-JOB", "operator")
        self.catalog.set_operation_phase(self.fence, "writing")
        with self.assertRaisesRegex(ValidationError, "waiting.media|checkpoint"):
            self.acknowledge("waiting_media")
        self.assertIsNone(self.catalog.job_management_state("NATIVE-JOB")["pause_acknowledged_at"])

    def test_controller_does_not_acknowledge_after_media_admission_or_mount(self) -> None:
        self.catalog.request_job_pause("NATIVE-JOB", "operator")
        for mounted in (False, True):
            with self.subTest(mounted=mounted):
                backend = SimpleNamespace(catalog=self.catalog)
                backend.wait_for_preformat_media = lambda _expected, _stop: True
                controller = self.controller(backend)
                controller._media_admitted = not mounted
                if mounted:
                    controller._mounted = SimpleNamespace(path=Path("/unused"))
                self.assertTrue(controller.wait_for_media(lambda: False))
                self.assertFalse(controller.pause_acknowledged)
                self.assertIsNone(self.catalog.job_management_state("NATIVE-JOB")["pause_acknowledged_at"])

    def test_controller_does_not_return_normally_with_nonquiescent_command(self) -> None:
        self.catalog.request_job_pause("NATIVE-JOB", "operator")
        self.catalog.reserve_hardware_command(self.fence, "reserved-probe", "probe_media", "a" * 64)
        controller = self.controller(SimpleNamespace(catalog=self.catalog))
        with self.assertRaises(CommandQuiescenceRequired):
            controller.wait_for_media(lambda: False)
        self.assertFalse(controller.pause_acknowledged)
        self.assertIsNone(self.catalog.job_management_state("NATIVE-JOB")["pause_acknowledged_at"])

    def test_pause_requested_during_successful_identify_waits_for_unload(self) -> None:
        def media_arrived(_expected, stop):
            self.assertFalse(stop())
            self.catalog.request_job_pause("NATIVE-JOB", "operator")
            return True

        backend = SimpleNamespace(
            catalog=self.catalog, wait_for_preformat_media=media_arrived,
        )
        controller = self.controller(backend)
        self.assertTrue(controller.wait_for_media(lambda: False))
        self.assertTrue(controller._media_admitted)
        self.assertFalse(controller.pause_acknowledged)
        self.assertIsNone(self.catalog.job_management_state("NATIVE-JOB")["pause_acknowledged_at"])

    def test_waiting_pause_refuses_different_current_sequence(self) -> None:
        self.catalog.request_job_pause("NATIVE-JOB", "operator")
        self.catalog.update_automatic_job("NATIVE-JOB", "waiting_media", current_sequence=2)
        with self.assertRaisesRegex(ValidationError, "waiting_media"):
            self.acknowledge("waiting_media")

    def test_waiting_pause_requires_a_fence(self) -> None:
        self.catalog.request_job_pause("NATIVE-JOB", "operator")
        with self.assertRaisesRegex(ValidationError, "fence"):
            self.catalog.acknowledge_job_pause("NATIVE-JOB", "waiting_media")

    def test_waiting_pause_can_resume_without_changing_frozen_layout(self) -> None:
        epoch = self.catalog.latest_layout_epoch("NATIVE-JOB")
        self.catalog.authorize_automatic_format_sequence(
            "NATIVE-JOB", expected_revision=self.catalog.job_management_state("NATIVE-JOB")["revision"],
            layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
            actor="operator", idempotency_key="pause-authority",
            authorized_at=self.record.started_at,
        )
        automatic_authority = dict(self.catalog.format_sequence_authorization("NATIVE-JOB", 1))
        before_cassette = dict(self.catalog.connection.execute(
            "SELECT * FROM automatic_cassettes WHERE job_id=?", ("NATIVE-JOB",)
        ).fetchone())
        before_authority = [tuple(row) for row in self.catalog.connection.execute(
            "SELECT * FROM format_confirmations WHERE operation_id=?", (self.record.id,)
        )]
        enabled = dict(self.catalog.enable_automatic_sequence_for_start(
            "NATIVE-JOB", actor="operator", enabled_at=self.record.started_at,
        ))
        self.catalog.request_job_pause("NATIVE-JOB", "operator")
        self.assertEqual("pause_pending", self.catalog.automatic_sequence_state("NATIVE-JOB")["state"])
        self.assertTrue(self.acknowledge("waiting_media"))
        self.assertEqual("disabled", self.catalog.automatic_sequence_state("NATIVE-JOB")["state"])
        audit = self.catalog.connection.execute(
            "SELECT payload_json FROM audit_entries WHERE action=? ORDER BY id DESC LIMIT 1",
            ("automatic.sequence.pause_checkpoint",),
        ).fetchone()
        self.assertEqual("waiting_media", json.loads(audit["payload_json"])["checkpoint"])
        self.catalog.clear_job_pause("NATIVE-JOB", "operator")
        resumed = self.catalog.enable_automatic_sequence_for_start(
            "NATIVE-JOB", actor="operator", enabled_at=self.record.started_at,
        )
        self.assertEqual("enabled", resumed["state"])
        for field in ("layout_epoch", "layout_fingerprint_sha256"):
            self.assertEqual(enabled[field], resumed[field])
        self.assertEqual(1, self.catalog.get_automatic_job("NATIVE-JOB")["current_sequence"])
        self.assertEqual(before_cassette, dict(self.catalog.connection.execute(
            "SELECT * FROM automatic_cassettes WHERE job_id=?", ("NATIVE-JOB",)
        ).fetchone()))
        self.assertEqual(before_authority, [tuple(row) for row in self.catalog.connection.execute(
            "SELECT * FROM format_confirmations WHERE operation_id=?", (self.record.id,)
        )])
        self.assertEqual(automatic_authority, dict(self.catalog.format_sequence_authorization("NATIVE-JOB", 1)))


if __name__ == "__main__":
    unittest.main()
