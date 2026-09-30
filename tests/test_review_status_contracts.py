from __future__ import annotations

import unittest

from pydantic import ValidationError

from ltobackup.daemon.api_models import DriveStatusV1, TelemetryV1


class ReviewStatusContractTests(unittest.TestCase):
    def test_unobserved_drive_fields_remain_unknown_on_wire(self):
        status = DriveStatusV1(
            state="unavailable", loaded=None, display_label="",
            cleaning_required=None, tape_alert_codes=None,
        ).model_dump(mode="json")
        self.assertIsNone(status["loaded"])
        self.assertIsNone(status["cleaning_required"])
        self.assertIsNone(status["tape_alert_codes"])

    def test_stale_sample_contract_preserves_age_and_gap(self):
        payload = dict(
            current_mib_per_second=None, effective_mib_per_second=12.5,
            current_sample_age_seconds=6.0, current_sample_stale=True,
            samples=({"event_id": 1, "occurred_at": "2026-09-04T21:00:00Z",
                      "mib_per_second": None},),
            durations=dict(copy_seconds=1, close_seconds=0,
                           finalization_seconds=0, unmount_seconds=0, unload_seconds=0),
        )
        result = TelemetryV1.model_validate(payload).model_dump(mode="json")
        self.assertTrue(result["current_sample_stale"])
        self.assertEqual(result["current_sample_age_seconds"], 6.0)
        self.assertIsNone(result["samples"][0]["mib_per_second"])
        with self.assertRaises(ValidationError):
            TelemetryV1.model_validate({**payload, "current_sample_age_seconds": -1})


if __name__ == "__main__":
    unittest.main()
