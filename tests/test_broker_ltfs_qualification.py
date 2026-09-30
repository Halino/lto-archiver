import hashlib
import hmac
import json
import os
import socket
import sqlite3
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import ltobackup.broker.store as broker_store_module
from ltobackup.broker.client import BrokerUnavailable, UnixBrokeredCgroupScopeApi
from ltobackup.broker.protocol import (
    BrokerProtocolError,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)
from ltobackup.broker.service import CommandBrokerService
from ltobackup.broker.store import (
    BrokerStateConflict,
    BrokerStateStore,
    BrokerStateUnavailable,
)
from ltobackup.qualification.broker_executor import BrokerQualificationExecutor
from ltobackup.qualification.broker_models import (
    BrokerQualificationDispatch,
    BrokerQualificationExecution,
    BrokerQualificationInspection,
    BrokerQualificationInspectionRequest,
    BrokerQualificationRequest,
    qualification_inspection_proof_payload,
    qualification_request_operation_token,
)
from ltobackup.qualification.plan import (
    QualificationOperation,
    QualificationPlan,
)
from ltobackup.tape.command_supervisor import BrokeredCgroupScopeToken

BOOT_ID = "11111111-2222-4333-8444-555555555555"
OTHER_BOOT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
NOW = "2026-08-23T12:34:56.000000Z"
CAPABILITY = b"c" * 32
PROOF_KEY = b"p" * 32
QUALIFICATION_CREDENTIAL = b"q" * 32
QUALIFICATION_ISSUED_NS = 1_787_474_936_000_000_000
QUALIFICATION_NOW_NS = QUALIFICATION_ISSUED_NS + 1
QUALIFICATION_EXPIRES_NS = QUALIFICATION_ISSUED_NS + 60_000_000_000
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


def _as_root_owned(status: os.stat_result) -> os.stat_result:
    fields = list(status)
    fields[4] = 0
    fields[5] = 0
    return os.stat_result(fields)


def _open_store(path: Path, *, boot_id: str = BOOT_ID) -> BrokerStateStore:
    with (
        patch("ltobackup.broker.store._effective_ids", return_value=(0, 0)),
        patch(
            "ltobackup.broker.store._fstat",
            side_effect=lambda fd: _as_root_owned(os.fstat(fd)),
        ),
        patch(
            "ltobackup.broker.store._stat_at",
            side_effect=lambda name, *, dir_fd: _as_root_owned(
                os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            ),
        ),
    ):
        return BrokerStateStore.open(path, boot_id=boot_id, clock=lambda: NOW)


def request_model(**overrides):
    token_override = overrides.pop("operation_token", None)
    fields = {
        "protocol_version": 1,
        "run_id": "11111111-1111-4111-8111-111111111111",
        "plan_sha256": "a" * 64,
        "stage_ordinal": 3,
        "operation": QualificationOperation.WIPE,
        "tape_device_identity_sha256": "c" * 64,
        "scsi_device_identity_sha256": "d" * 64,
        "expected_media_scope_sha256": "e" * 64,
        "observed_media_identity_sha256": "f" * 64,
        "expected_physical_label": r"CURRENT/LABEL\EXACT",
        # Catalog tape_serial is logical legacy data.  The cartridge MAM
        # Medium Serial Number (0x0401) is independently bound by the observed
        # digest; the compatibility field never carries application Volume
        # Identifier (0x0008).
        "expected_tape_serial": "CATALOG-SERIAL",
        "expected_drive_serial": "DRIVE-SERIAL",
        "expected_drive_wwid": "0x5000000000000001",
        "expected_volume_uuid": "22222222-2222-4222-8222-222222222222",
        "expected_generation": 7,
        "issued_at_ns": QUALIFICATION_ISSUED_NS,
        "expires_at_ns": QUALIFICATION_EXPIRES_NS,
        "request_nonce": b"n" * 32,
    }
    fields.update(overrides)
    if fields["operation"] is QualificationOperation.FORMAT:
        # A successful new FORMAT fixture explicitly authorizes this fixed MAM serial.
        plan = QualificationPlan(
            schema=2,
            run_id=fields["run_id"],
            job_id="qualification-job",
            cassette_sequence=1,
            physical_label=fields["expected_physical_label"],
            tape_serial=fields["expected_tape_serial"],
            drive_serial=fields["expected_drive_serial"],
            drive_wwid=fields["expected_drive_wwid"],
            linux_tree_sha256="a" * 64,
            ltfs_tree_sha256="b" * 64,
            ltfs_rpm_sha256="c" * 64,
            issued_at_ns=fields["issued_at_ns"],
            expires_at_ns=fields["expires_at_ns"],
            operations=(QualificationOperation.FORMAT,),
            expected_mam_medium_serial="CURRENT-SERIAL",
        )
        fields.update(
            protocol_version=2,
            plan_sha256=plan.plan_sha256,
            canonical_plan_json=plan.canonical_bytes().decode("utf-8"),
        )
    unsigned = BrokerQualificationRequest(
        **fields,
        operation_token="0" * 64,
    )
    return replace(
        unsigned,
        operation_token=(
            token_override
            or qualification_request_operation_token(unsigned, QUALIFICATION_CREDENTIAL)
        ),
    )


def terminal_model(request=None, **overrides):
    request = request or request_model()
    fields = {
        "protocol_version": 1,
        "run_id": request.run_id,
        "stage_ordinal": request.stage_ordinal,
        "operation": request.operation,
        "request_sha256": request.request_sha256,
        "dispatch_state": "terminal",
        "terminal_receipt_sha256": "1" * 64,
        "child_exit_code": 1,
        "evidence_sha256": "2" * 64,
        "broker_nonce": b"o" * 32,
        "broker_proof": b"p" * 32,
    }
    fields.update(overrides)
    return BrokerQualificationDispatch(**fields)


def inspection_request(**overrides):
    fields = {
        "run_id": "11111111-1111-4111-8111-111111111111",
        "stage_ordinal": 3,
        "challenge": b"h" * 32,
    }
    fields.update(overrides)
    return BrokerQualificationInspectionRequest(**fields)


def inspection_snapshot(request=None, **overrides):
    request = request or inspection_request()
    fields = {
        "run_id": request.run_id,
        "stage_ordinal": request.stage_ordinal,
        "state": "TERMINAL",
        "boot_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "request_sha256": "a" * 64,
        "immutable_sha256": "b" * 64,
        "plan_sha256": "c" * 64,
        "operation": "wipe",
        "operation_token_sha256": "d" * 64,
        "tape_device_identity_sha256": "e" * 64,
        "scsi_device_identity_sha256": "f" * 64,
        "expected_media_scope_sha256": "0" * 64,
        "observed_media_identity_sha256": "1" * 64,
        "expected_physical_label": "CURRENT-LABEL",
        "expected_tape_serial": "CURRENT-SERIAL",
        "expected_drive_serial": "DRIVE-SERIAL",
        "expected_drive_wwid": "0x5000000000000001",
        "expected_volume_uuid": "22222222-2222-4222-8222-222222222222",
        "expected_generation": 7,
        "request_nonce": b"n" * 32,
        "created_at": NOW,
        "dispatched_at": NOW,
        "terminal_at": NOW,
    }
    fields.update(overrides)
    return fields


def inspection_model(request=None, **overrides):
    request = request or inspection_request()
    snapshot = inspection_snapshot(request)
    dispatch = BrokerQualificationDispatch(
        protocol_version=1,
        run_id=request.run_id,
        stage_ordinal=request.stage_ordinal,
        operation=QualificationOperation.WIPE,
        request_sha256=snapshot["request_sha256"],
        dispatch_state="terminal",
        terminal_receipt_sha256="2" * 64,
        child_exit_code=1,
        evidence_sha256="3" * 64,
        broker_nonce=b"o" * 32,
        broker_proof=b"p" * 32,
    )
    fields = {
        "state": "terminal",
        "stage_snapshot": snapshot,
        "dispatch": dispatch,
        "observation_nonce": b"v" * 32,
        "proof": b"w" * 32,
    }
    fields.update(overrides)
    return BrokerQualificationInspection(**fields)


class BrokerLtfsQualificationProtocolTests(unittest.TestCase):
    def test_inspection_models_are_closed_and_proof_binds_every_field(self):
        request = inspection_request()
        inspection = inspection_model(request)
        self.assertEqual(inspection.state, "terminal")
        self.assertEqual(inspection.stage_snapshot["run_id"], request.run_id)
        for mutation in (
            {"run_id": "not-a-uuid"},
            {"stage_ordinal": 0},
            {"stage_ordinal": True},
            {"challenge": b"short"},
            {"challenge": b"h" * 33},
        ):
            with self.subTest(request=mutation), self.assertRaises(ValueError):
                inspection_request(**mutation)
        for state, durable_state in (
            ("pre_dispatch", "PREPARED"),
            ("dispatched", "DISPATCHED"),
            ("fenced", "FENCED"),
        ):
            with self.subTest(state=state):
                model = inspection_model(
                    request,
                    state=state,
                    stage_snapshot=inspection_snapshot(
                        request,
                        state=durable_state,
                        dispatched_at=(None if state == "pre_dispatch" else NOW),
                        terminal_at=(NOW if state == "fenced" else None),
                    ),
                    dispatch=None,
                )
                self.assertEqual(model.state, state)
        self.assertEqual(
            inspection_model(
                request,
                state="missing",
                stage_snapshot=None,
                dispatch=None,
            ).state,
            "missing",
        )
        for mutation in (
            {"state": "unknown"},
            {"state": "terminal", "dispatch": None},
            {"state": "dispatched", "dispatch": inspection.dispatch},
            {"state": "missing", "stage_snapshot": inspection.stage_snapshot},
            {
                "stage_snapshot": inspection_snapshot(
                    request, expected_physical_label="x" * 256
                )
            },
        ):
            with self.subTest(inspection=mutation), self.assertRaises(ValueError):
                inspection_model(request, **mutation)

    @staticmethod
    def _signed_inspection(
        request: BrokerQualificationInspectionRequest,
    ) -> BrokerQualificationInspection:
        inspection = inspection_model(request)
        return replace(
            inspection,
            proof=hmac.new(
                b"k" * 32,
                qualification_inspection_proof_payload(request, inspection),
                hashlib.sha256,
            ).digest(),
        )

    def _assert_hmac_rejects_substitution(
        self,
        request: BrokerQualificationInspectionRequest,
        inspection: BrokerQualificationInspection,
        *,
        mutated_request: BrokerQualificationInspectionRequest | None = None,
        mutated_inspection: BrokerQualificationInspection | None = None,
    ) -> None:
        candidate_request = mutated_request or request
        candidate_inspection = mutated_inspection or inspection
        expected = hmac.new(
            b"k" * 32,
            qualification_inspection_proof_payload(
                candidate_request, candidate_inspection
            ),
            hashlib.sha256,
        ).digest()
        self.assertFalse(hmac.compare_digest(candidate_inspection.proof, expected))

    def test_inspection_proof_mutation_matrix_is_closed_and_cross_bound(self):
        request = inspection_request()
        inspection = self._signed_inspection(request)

        for field, value in (
            ("run_id", "21111111-1111-4111-8111-111111111111"),
            ("stage_ordinal", 4),
            ("challenge", b"x" * 32),
        ):
            with self.subTest(request_field=field):
                self._assert_hmac_rejects_substitution(
                    request,
                    inspection,
                    mutated_request=replace(request, **{field: value}),
                )

        for field, value in (
            ("boot_id", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            ("immutable_sha256", "9" * 64),
            ("plan_sha256", "8" * 64),
            ("operation_token_sha256", "7" * 64),
            ("tape_device_identity_sha256", "6" * 64),
            ("scsi_device_identity_sha256", "5" * 64),
            ("expected_media_scope_sha256", "4" * 64),
            ("observed_media_identity_sha256", "3" * 64),
            ("expected_physical_label", "SUBSTITUTED-LABEL"),
            ("expected_tape_serial", "SUBSTITUTED-SERIAL"),
            ("expected_drive_serial", "SUBSTITUTED-DRIVE"),
            ("expected_drive_wwid", "0x5000000000000002"),
            ("expected_volume_uuid", "33333333-3333-4333-8333-333333333333"),
            ("expected_generation", 8),
            ("request_nonce", b"z" * 32),
            ("created_at", "2026-08-23T12:34:57.000000Z"),
            ("dispatched_at", "2026-08-23T12:34:57.000000Z"),
            ("terminal_at", "2026-08-23T12:34:57.000000Z"),
        ):
            with self.subTest(snapshot_field=field):
                snapshot = dict(inspection.stage_snapshot)
                snapshot[field] = value
                self._assert_hmac_rejects_substitution(
                    request,
                    inspection,
                    mutated_inspection=replace(inspection, stage_snapshot=snapshot),
                )

        for field, value in (
            ("run_id", "21111111-1111-4111-8111-111111111111"),
            ("stage_ordinal", 4),
            ("state", "DISPATCHED"),
            ("request_sha256", "9" * 64),
            ("operation", "format"),
        ):
            with self.subTest(cross_identity_snapshot_field=field):
                snapshot = dict(inspection.stage_snapshot)
                snapshot[field] = value
                with self.assertRaises(ValueError):
                    replace(inspection, stage_snapshot=snapshot)

        for field, value in (("state", "UNKNOWN"), ("operation", "unknown")):
            with self.subTest(invalid_snapshot_enum=field):
                snapshot = dict(inspection.stage_snapshot)
                snapshot[field] = value
                with self.assertRaises(ValueError):
                    replace(inspection, stage_snapshot=snapshot)

        for field, value in (
            ("run_id", "21111111-1111-4111-8111-111111111111"),
            ("stage_ordinal", 4),
            ("request_sha256", "9" * 64),
        ):
            with self.subTest(cross_identity_dispatch_field=field):
                dispatch = replace(inspection.dispatch, **{field: value})
                with self.assertRaises(ValueError):
                    replace(inspection, dispatch=dispatch)

        for field, value in (
            ("protocol_version", 2),
            ("operation", QualificationOperation.FORMAT),
            ("dispatch_state", "dispatched"),
            ("child_exit_code", 0),
        ):
            with (
                self.subTest(cross_identity_dispatch_field=field),
                self.assertRaises(ValueError),
            ):
                replace(inspection.dispatch, **{field: value})

        for field, value in (
            ("operation", "unknown"),
            ("dispatch_state", "unknown"),
        ):
            with (
                self.subTest(invalid_dispatch_enum=field),
                self.assertRaises(ValueError),
            ):
                replace(inspection.dispatch, **{field: value})

        for field, value in (
            ("terminal_receipt_sha256", "9" * 64),
            ("evidence_sha256", "8" * 64),
            ("broker_nonce", b"x" * 32),
            ("broker_proof", b"y" * 32),
        ):
            with self.subTest(dispatch_field=field):
                self._assert_hmac_rejects_substitution(
                    request,
                    inspection,
                    mutated_inspection=replace(
                        inspection,
                        dispatch=replace(inspection.dispatch, **{field: value}),
                    ),
                )

        for field, value in (
            ("state", "fenced"),
            ("observation_nonce", b"x" * 32),
            ("proof", b"x" * 32),
        ):
            with self.subTest(outer_field=field):
                if field == "state":
                    snapshot = dict(inspection.stage_snapshot)
                    snapshot["state"] = "FENCED"
                    candidate = replace(
                        inspection,
                        state=value,
                        stage_snapshot=snapshot,
                        dispatch=None,
                    )
                else:
                    candidate = replace(inspection, **{field: value})
                self._assert_hmac_rejects_substitution(
                    request, inspection, mutated_inspection=candidate
                )

        for field, value in (
            ("observation_nonce", b"short"),
            ("observation_nonce", b"x" * 33),
            ("proof", b"short"),
            ("proof", b"x" * 33),
        ):
            with (
                self.subTest(outer_length_field=field, value=value),
                self.assertRaises(ValueError),
            ):
                replace(inspection, **{field: value})

        for field, value in (
            ("request_nonce", b"short"),
            ("request_nonce", b"x" * 33),
        ):
            with self.subTest(snapshot_length_field=field, value=value):
                snapshot = dict(inspection.stage_snapshot)
                snapshot[field] = value
                with self.assertRaises(ValueError):
                    replace(inspection, stage_snapshot=snapshot)

        for mutate in (
            lambda snapshot: snapshot.pop("plan_sha256"),
            lambda snapshot: snapshot.update(extra=True),
        ):
            with self.subTest(snapshot_schema=mutate):
                snapshot = dict(inspection.stage_snapshot)
                mutate(snapshot)
                with self.assertRaises(ValueError):
                    replace(inspection, stage_snapshot=snapshot)

    def test_inspection_wire_schema_is_closed_and_causally_bound(self):
        request = inspection_request()
        inspection = inspection_model(request)
        request_packet = encode_request(
            "inspect_ltfs_qualification_stage",
            request_id=b"i" * 32,
            capability=b"c" * 32,
            params={"request": request},
        )
        request_wire = json.loads(request_packet)
        self.assertEqual(
            set(request_wire["params"]["request"]),
            {"run_id", "stage_ordinal", "challenge"},
        )
        decoded_request = decode_request(request_packet)
        self.assertEqual(decoded_request.params["request"], request)
        response_packet = encode_response(
            "inspect_ltfs_qualification_stage",
            request_id=b"i" * 32,
            result={"inspection": inspection},
        )
        response_wire = json.loads(response_packet)
        self.assertEqual(
            set(response_wire["result"]["inspection"]),
            {"state", "stage_snapshot", "dispatch", "observation_nonce", "proof"},
        )
        self.assertEqual(
            decode_response(response_packet, request=decoded_request).result[
                "inspection"
            ],
            inspection,
        )
        for bad_params in ({}, {"request": request, "extra": True}):
            with (
                self.subTest(params=bad_params),
                self.assertRaises(BrokerProtocolError),
            ):
                encode_request(
                    "inspect_ltfs_qualification_stage",
                    request_id=b"i" * 32,
                    capability=b"c" * 32,
                    params=bad_params,
                )
        for bad_result in (
            {},
            {"inspection": inspection, "extra": True},
        ):
            with (
                self.subTest(result=bad_result),
                self.assertRaises(BrokerProtocolError),
            ):
                encode_response(
                    "inspect_ltfs_qualification_stage",
                    request_id=b"i" * 32,
                    result=bad_result,
                )
        with self.assertRaises(BrokerProtocolError):
            decode_response(
                response_packet,
                request=decode_request(
                    encode_request(
                        "inspect_ltfs_qualification_stage",
                        request_id=b"i" * 32,
                        capability=b"c" * 32,
                        params={
                            "request": inspection_request(
                                run_id="21111111-1111-4111-8111-111111111111"
                            )
                        },
                    )
                ),
            )

    def test_closed_request_and_terminal_response_round_trip(self):
        model = request_model()
        encoded_request = encode_request(
            "execute_ltfs_qualification_stage",
            request_id=b"i" * 32,
            capability=b"c" * 32,
            params={"request": model},
        )
        decoded_request = decode_request(encoded_request)
        self.assertEqual(model, decoded_request.params["request"])

        terminal = terminal_model(model)
        encoded_response = encode_response(
            "execute_ltfs_qualification_stage",
            request_id=b"i" * 32,
            result={"dispatch": terminal},
        )
        decoded_response = decode_response(encoded_response, request=decoded_request)
        self.assertEqual(terminal, decoded_response.result["dispatch"])

    def test_request_and_response_are_bound_to_exact_operation(self):
        model = request_model()
        decoded_request = decode_request(
            encode_request(
                "execute_ltfs_qualification_stage",
                request_id=b"i" * 32,
                capability=b"c" * 32,
                params={"request": model},
            )
        )
        substituted = replace(
            terminal_model(model),
            operation=QualificationOperation.FORMAT,
            child_exit_code=0,
        )
        with self.assertRaises(BrokerProtocolError):
            decode_response(
                encode_response(
                    "execute_ltfs_qualification_stage",
                    request_id=b"i" * 32,
                    result={"dispatch": substituted},
                ),
                request=decoded_request,
            )

    def test_mutated_historical_long_wipe_request_cannot_be_authorized(self):
        request = request_model(operation=QualificationOperation.WIPE)
        object.__setattr__(request, "operation", QualificationOperation.LONG_WIPE)
        with self.assertRaisesRegex(ValueError, "operation"):
            qualification_request_operation_token(request, QUALIFICATION_CREDENTIAL)

    def test_models_reject_noncanonical_uuid_unknown_operation_and_bad_exit(self):
        for mutation in (
            {"run_id": "not-a-uuid"},
            {"operation": "raw_scsi"},
            {"stage_ordinal": True},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                request_model(**mutation)
        with self.assertRaises(ValueError):
            terminal_model(child_exit_code=2)
        with self.assertRaisesRegex(ValueError, "operation"):
            request_model(operation=QualificationOperation.LONG_WIPE)
        with self.assertRaisesRegex(ValueError, "operation"):
            terminal_model(
                request_model(),
                operation=QualificationOperation.LONG_WIPE,
                child_exit_code=1,
            )
        with self.assertRaises(ValueError):
            terminal_model(
                request_model(operation=QualificationOperation.WIPE),
                operation=QualificationOperation.WIPE,
                child_exit_code=0,
            )
        self.assertEqual(
            terminal_model(
                request_model(operation=QualificationOperation.REPAIR),
                operation=QualificationOperation.REPAIR,
                child_exit_code=1,
            ).child_exit_code,
            1,
        )


class BrokerLtfsQualificationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "state.db"

    def test_request_is_durable_before_dispatch_and_terminal_is_idempotent(self):
        request = request_model()
        terminal = terminal_model(request)
        with _open_store(self.path) as store:
            prepared = store.prepare_ltfs_qualification(request)
            self.assertTrue(prepared.transitioned)
            self.assertEqual(prepared.record.state, "PREPARED")
            dispatched = store.mark_ltfs_qualification_dispatched(request)
            self.assertTrue(dispatched.transitioned)
            self.assertEqual(dispatched.record.state, "DISPATCHED")
            completed = store.complete_ltfs_qualification(request, terminal)
            self.assertTrue(completed.transitioned)
            self.assertEqual(completed.record.state, "TERMINAL")
            replay = store.complete_ltfs_qualification(request, terminal)
            self.assertFalse(replay.transitioned)
            self.assertEqual(replay.record, completed.record)

            with self.assertRaises(BrokerStateConflict):
                store.prepare_ltfs_qualification(
                    replace(request, operation_token="9" * 64)
                )

        with _open_store(self.path) as reopened:
            self.assertEqual(
                reopened.ltfs_qualification_stage(
                    request.run_id, request.stage_ordinal
                ),
                completed.record,
            )

    def test_repair_corrected_exit_is_durable_and_reopens(self):
        request = request_model(operation=QualificationOperation.REPAIR)
        terminal = terminal_model(
            request,
            operation=QualificationOperation.REPAIR,
            child_exit_code=1,
        )
        with _open_store(self.path) as store:
            store.prepare_ltfs_qualification(request)
            store.mark_ltfs_qualification_dispatched(request)
            completed = store.complete_ltfs_qualification(request, terminal)
            self.assertEqual(completed.record.state, "TERMINAL")
            self.assertEqual(completed.record.child_exit_code, 1)

        with _open_store(self.path) as reopened:
            record = reopened.ltfs_qualification_stage(
                request.run_id, request.stage_ordinal
            )
            self.assertIsNotNone(record)
            self.assertEqual(record.state, "TERMINAL")
            self.assertEqual(record.child_exit_code, 1)

    def test_restart_fences_predispatch_and_dispatched_rows_without_retry(self):
        for stage_ordinal, dispatched in ((1, False), (2, True)):
            with self.subTest(dispatched=dispatched):
                request = request_model(
                    stage_ordinal=stage_ordinal,
                    request_nonce=bytes([stage_ordinal]) * 32,
                )
                path = Path(self.temporary.name) / f"restart-{stage_ordinal}.db"
                with _open_store(path) as store:
                    store.prepare_ltfs_qualification(request)
                    if dispatched:
                        store.mark_ltfs_qualification_dispatched(request)

                with _open_store(path, boot_id=OTHER_BOOT_ID) as reopened:
                    record = reopened.ltfs_qualification_stage(
                        request.run_id, request.stage_ordinal
                    )
                    self.assertIsNotNone(record)
                    self.assertEqual(record.state, "FENCED")
                    replay = reopened.prepare_ltfs_qualification(request)
                    self.assertFalse(replay.transitioned)
                    self.assertEqual(replay.record.state, "FENCED")
                    with self.assertRaises(BrokerStateConflict):
                        reopened.mark_ltfs_qualification_dispatched(request)

    def test_same_boot_restart_fences_dispatch_and_blocks_every_new_run(self):
        abandoned = request_model(stage_ordinal=1)
        distinct = request_model(
            run_id="21111111-1111-4111-8111-111111111111",
            stage_ordinal=1,
            request_nonce=b"q" * 32,
        )
        with _open_store(self.path) as store:
            store.prepare_ltfs_qualification(abandoned)
            store.mark_ltfs_qualification_dispatched(abandoned)

        with _open_store(self.path) as restarted:
            record = restarted.ltfs_qualification_stage(
                abandoned.run_id, abandoned.stage_ordinal
            )
            self.assertIsNotNone(record)
            self.assertEqual("FENCED", record.state)
            self.assertFalse(restarted.ltfs_sessions_ready())
            with self.assertRaises(BrokerStateConflict):
                restarted.prepare_ltfs_qualification(distinct)

    def test_exact_schema_eight_migrates_to_empty_schema_nine_table(self):
        _open_store(self.path).close()
        connection = sqlite3.connect(self.path)
        connection.execute("DROP TABLE ltfs_qualification_stages")
        connection.execute("PRAGMA user_version=8")
        connection.commit()
        connection.close()

        with _open_store(self.path) as migrated:
            self.assertEqual(migrated.pragma("user_version"), 10)
            self.assertIsNone(
                migrated.ltfs_qualification_stage(
                    "11111111-1111-4111-8111-111111111111", 1
                )
            )

    def _downgrade_current_store_to_v9(self, *, populated: bool) -> None:
        with _open_store(self.path) as store:
            if populated:
                store.prepare_ltfs_qualification(request_model())
        connection = sqlite3.connect(self.path)
        current_columns = tuple(
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(ltfs_qualification_stages)"
            )
            if row[1] not in {"expected_drive_serial", "expected_drive_wwid"}
        )
        rows = connection.execute(
            "SELECT " + ",".join(current_columns) + " FROM ltfs_qualification_stages"
        ).fetchall()
        connection.execute("DROP TABLE ltfs_qualification_stages")
        connection.execute(broker_store_module._LTFS_QUALIFICATION_STAGES_V9_SQL)
        if rows:
            connection.executemany(
                "INSERT INTO ltfs_qualification_stages("
                + ",".join(current_columns)
                + ") VALUES("
                + ",".join("?" for _column in current_columns)
                + ")",
                rows,
            )
        connection.execute("PRAGMA user_version=9")
        connection.commit()
        connection.close()
        self.path.chmod(0o600)

    def test_empty_version_nine_adds_drive_identity_columns(self):
        self._downgrade_current_store_to_v9(populated=False)
        with _open_store(self.path) as migrated:
            self.assertEqual(migrated.pragma("user_version"), 10)
            columns = {
                row[1]
                for row in migrated._connection.execute(
                    "PRAGMA table_info(ltfs_qualification_stages)"
                )
            }
        self.assertTrue(
            {"expected_drive_serial", "expected_drive_wwid"}.issubset(columns)
        )

    def test_populated_version_nine_fails_closed_without_rewriting_authority(self):
        self._downgrade_current_store_to_v9(populated=True)
        with self.assertRaises(BrokerStateUnavailable):
            _open_store(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (9,))
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM ltfs_qualification_stages"
                ).fetchone(),
                (1,),
            )
        finally:
            connection.close()


class _QualificationExecutor:
    def __init__(self) -> None:
        self.requests = []
        self.fail = False

    def _execute(self, request):
        self.requests.append(request)
        if self.fail:
            raise RuntimeError("injected post-dispatch ambiguity")
        exit_code = 1 if request.operation is QualificationOperation.WIPE else 0
        return BrokerQualificationExecution("1" * 64, exit_code, "2" * 64)

    read_only = _execute
    additive_write = _execute
    format = _execute
    overwrite = _execute
    repair = _execute
    wipe = _execute
    unload = _execute
    load = _execute
    eject = _execute


class _SupportedOnlyQualificationExecutor:
    def execute(self, _request):
        raise AssertionError("qualification dispatch was not expected")

    read_only = execute
    additive_write = execute
    format = execute
    overwrite = execute
    repair = execute
    wipe = execute
    unload = execute
    load = execute
    eject = execute


class BrokerLtfsQualificationServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "state.db"
        self.store = _open_store(self.path)
        self.addCleanup(self.store.close)
        self.driver = _QualificationExecutor()
        self.executor = BrokerQualificationExecutor(
            self.driver,
            credential=QUALIFICATION_CREDENTIAL,
            now_ns=lambda: QUALIFICATION_NOW_NS,
        )
        self.service = CommandBrokerService(
            self.store,
            object(),
            capability=CAPABILITY,
            proof_key=PROOF_KEY,
            daemon_uid=os.getuid(),
            daemon_gid=os.getgid(),
            enforcing=False,
            daemon_context="system_u:system_r:lto_archiver_t:s0",
            connection_timeout=0.5,
            qualification_executor=self.executor,
        )

    def _peer_auth_service(self) -> CommandBrokerService:
        return CommandBrokerService(
            self.store,
            object(),
            capability=CAPABILITY,
            proof_key=PROOF_KEY,
            daemon_uid=991,
            daemon_gid=991,
            enforcing=True,
            daemon_context="system_u:system_r:lto_archiver_t:s0",
            connection_timeout=0.5,
            qualification_executor=self.executor,
        )

    def test_broker_executor_does_not_require_a_long_wipe_driver_method(self):
        executor = BrokerQualificationExecutor(
            _SupportedOnlyQualificationExecutor(),
            credential=QUALIFICATION_CREDENTIAL,
            now_ns=lambda: QUALIFICATION_NOW_NS,
        )
        self.assertIsInstance(executor, BrokerQualificationExecutor)

    @staticmethod
    def _exchange_as(
        service: CommandBrokerService,
        packet: bytes,
        identity: tuple[int, int, bytes | None],
    ):
        request = decode_request(packet)
        client_socket, service_socket = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET
        )
        try:
            client_socket.send(packet)
            with patch(
                "ltobackup.broker.service._peer_identity", return_value=identity
            ):
                service.handle_connection(service_socket)
            return decode_response(client_socket.recv(65537), request=request)
        finally:
            client_socket.close()
            service_socket.close()

    def test_root_peer_may_execute_and_inspect_qualification_stages(self):
        service = self._peer_auth_service()
        request = request_model()
        context = b"system_u:system_r:lto_archiver_t:s0"

        executed = self._exchange_as(
            service,
            encode_request(
                "execute_ltfs_qualification_stage",
                request_id=b"e" * 32,
                capability=CAPABILITY,
                params={"request": request},
            ),
            (0, 0, context),
        )
        inspected = self._exchange_as(
            service,
            encode_request(
                "inspect_ltfs_qualification_stage",
                request_id=b"i" * 32,
                capability=CAPABILITY,
                params={
                    "request": BrokerQualificationInspectionRequest(
                        request.run_id,
                        request.stage_ordinal,
                        b"h" * 32,
                    )
                },
            ),
            (0, 0, context),
        )

        self.assertIsNone(executed.error_code)
        self.assertEqual(executed.result["dispatch"].dispatch_state, "terminal")
        self.assertIsNone(inspected.error_code)
        self.assertEqual(inspected.result["inspection"].state, "terminal")
        self.assertEqual(self.driver.requests, [request])

    def test_root_peer_cannot_mutate_nonqualification_broker_state(self):
        service = self._peer_auth_service()
        before_changes = self.store._connection.total_changes

        response = self._exchange_as(
            service,
            encode_request(
                "create_scope",
                request_id=b"c" * 32,
                capability=CAPABILITY,
                params={
                    "command_id": "root-must-not-create-scope",
                    "owner_generation": 1,
                    "request_nonce": b"n" * 32,
                },
            ),
            (0, 0, b"system_u:system_r:lto_archiver_t:s0"),
        )

        self.assertEqual(response.error_code, "auth.denied")
        self.assertEqual(self.store._connection.total_changes, before_changes)
        self.assertEqual(self.store.scopes_for_reconciliation(), ())

    def test_root_qualification_peer_requires_root_gid_and_daemon_context(self):
        service = self._peer_auth_service()
        request = request_model()
        before_changes = self.store._connection.total_changes
        for request_id, identity in (
            (b"g" * 32, (0, 991, b"system_u:system_r:lto_archiver_t:s0")),
            (b"s" * 32, (0, 0, b"system_u:system_r:wrong_t:s0")),
        ):
            with self.subTest(identity=identity):
                response = self._exchange_as(
                    service,
                    encode_request(
                        "execute_ltfs_qualification_stage",
                        request_id=request_id,
                        capability=CAPABILITY,
                        params={"request": request},
                    ),
                    identity,
                )
                self.assertEqual(response.error_code, "auth.denied")
                self.assertEqual(self.store._connection.total_changes, before_changes)
        self.assertEqual(self.driver.requests, [])

    def test_daemon_peer_remains_authorized_for_qualification_stages(self):
        service = self._peer_auth_service()
        request = request_model()

        response = self._exchange_as(
            service,
            encode_request(
                "execute_ltfs_qualification_stage",
                request_id=b"d" * 32,
                capability=CAPABILITY,
                params={"request": request},
            ),
            (991, 991, b"system_u:system_r:lto_archiver_t:s0"),
        )

        self.assertIsNone(response.error_code)
        self.assertEqual(response.result["dispatch"].dispatch_state, "terminal")
        self.assertEqual(self.driver.requests, [request])

    def test_invalid_capability_is_rejected_before_method_aware_peer_auth(self):
        service = self._peer_auth_service()
        request = request_model()
        before_changes = self.store._connection.total_changes
        packets = (
            encode_request(
                "execute_ltfs_qualification_stage",
                request_id=b"q" * 32,
                capability=b"x" * 32,
                params={"request": request},
            ),
            encode_request(
                "create_scope",
                request_id=b"r" * 32,
                capability=b"x" * 32,
                params={
                    "command_id": "capability-first",
                    "owner_generation": 1,
                    "request_nonce": b"z" * 32,
                },
            ),
        )
        for packet in packets:
            request_structure = decode_request(packet)
            client_socket, service_socket = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET
            )
            try:
                client_socket.send(packet)
                with patch(
                    "ltobackup.broker.service._peer_identity",
                    side_effect=AssertionError("peer auth ran before capability"),
                ):
                    service.handle_connection(service_socket)
                response = decode_response(
                    client_socket.recv(65537), request=request_structure
                )
            finally:
                client_socket.close()
                service_socket.close()
            self.assertEqual(response.error_code, "auth.denied")
            self.assertEqual(self.store._connection.total_changes, before_changes)
        self.assertEqual(self.driver.requests, [])

    def _execute(self, request):
        client_socket, service_socket = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET
        )
        client = UnixBrokeredCgroupScopeApi.from_connected_socket(
            client_socket,
            BrokeredCgroupScopeToken(CAPABILITY),
            expected_peer_uid=os.getuid(),
        )
        worker = threading.Thread(
            target=self.service.handle_connection, args=(service_socket,)
        )
        worker.start()
        try:
            return client.execute_ltfs_qualification_stage(request)
        finally:
            client._discard_connected_socket()
            worker.join(timeout=2)
            service_socket.close()

    def _inspect(self, request):
        client_socket, service_socket = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET
        )
        client = UnixBrokeredCgroupScopeApi.from_connected_socket(
            client_socket,
            BrokeredCgroupScopeToken(CAPABILITY),
            expected_peer_uid=os.getuid(),
        )
        worker = threading.Thread(
            target=self.service.handle_connection, args=(service_socket,)
        )
        worker.start()
        try:
            return client.inspect_ltfs_qualification_stage(request)
        finally:
            client._discard_connected_socket()
            worker.join(timeout=2)
            service_socket.close()

    def test_execute_uses_ltfs_lifecycle_timeout(self):
        request = request_model()
        client_socket, service_socket = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET
        )
        client = UnixBrokeredCgroupScopeApi.from_connected_socket(
            client_socket,
            BrokeredCgroupScopeToken(CAPABILITY),
            timeout=5.0,
            ltfs_lifecycle_timeout=123.0,
            expected_peer_uid=os.getuid(),
        )
        worker = threading.Thread(
            target=self.service.handle_connection, args=(service_socket,)
        )
        worker.start()
        try:
            with patch.object(
                client, "_take_socket", wraps=client._take_socket
            ) as take_socket:
                dispatch = client.execute_ltfs_qualification_stage(request)
            take_socket.assert_called_once_with(timeout=123.0)
            self.assertEqual(dispatch.dispatch_state, "terminal")
        finally:
            client._discard_connected_socket()
            worker.join(timeout=2)
            service_socket.close()

    def test_authenticated_terminal_replay_never_executes_twice(self):
        request = request_model()
        first = self._execute(request)
        second = self._execute(request)
        self.assertEqual(first, second)
        self.assertEqual(self.driver.requests, [request])
        self.assertEqual(first.dispatch_state, "terminal")

    def test_store_inspection_returns_an_immutable_terminal_snapshot_without_writes(
        self,
    ):
        request = request_model()
        self._execute(request)
        before_bytes = self.path.read_bytes()
        before_changes = self.store._connection.total_changes

        snapshot = self.store.inspect_ltfs_qualification_stage(
            request.run_id, request.stage_ordinal
        )

        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertEqual(snapshot["state"], "TERMINAL")
        with self.assertRaises(TypeError):
            snapshot["state"] = "FENCED"
        self.assertEqual(self.path.read_bytes(), before_bytes)
        self.assertEqual(self.store._connection.total_changes, before_changes)
        self.assertEqual(self.driver.requests, [request])

    def test_authenticated_inspection_reads_prepared_state_without_executor_lock_or_fd_calls(
        self,
    ):
        request = request_model()
        self.store.prepare_ltfs_qualification(request)
        inspection_request = BrokerQualificationInspectionRequest(
            run_id=request.run_id,
            stage_ordinal=request.stage_ordinal,
            challenge=b"i" * 32,
        )
        before_bytes = self.path.read_bytes()
        before_changes = self.store._connection.total_changes

        class ExplodingExecutor:
            calls = 0

            def execute(self, _request):
                self.calls += 1
                raise AssertionError("inspection reached the qualification executor")

        class ExplodingLock:
            calls = 0

            def __enter__(self):
                self.calls += 1
                raise AssertionError("inspection acquired the LTFS lock")

            def __exit__(self, *_args):
                raise AssertionError("inspection acquired the LTFS lock")

        executor = ExplodingExecutor()
        lock = ExplodingLock()
        self.service._qualification_executor = executor
        self.service._ltfs_lock = lock
        with patch("ltobackup.broker.service.os.open", side_effect=AssertionError):
            inspection = self._inspect(inspection_request)

        self.assertEqual(inspection.state, "pre_dispatch")
        self.assertEqual(inspection.stage_snapshot["state"], "PREPARED")
        self.assertIsNone(inspection.dispatch)
        self.assertEqual(self.path.read_bytes(), before_bytes)
        self.assertEqual(self.store._connection.total_changes, before_changes)
        self.assertEqual(executor.calls, 0)
        self.assertEqual(lock.calls, 0)
        self.assertEqual(self.driver.requests, [])

    def test_authenticated_inspection_maps_every_durable_state_without_transition(self):
        prepared = request_model(stage_ordinal=4, request_nonce=b"4" * 32)
        terminal = request_model(stage_ordinal=6, request_nonce=b"6" * 32)
        self._execute(terminal)
        self.store.prepare_ltfs_qualification(prepared)
        observations = [
            (terminal, "terminal", "TERMINAL"),
            (prepared, "pre_dispatch", "PREPARED"),
        ]
        for index, (request, state, durable_state) in enumerate(observations, 1):
            with self.subTest(state=state):
                before_bytes = self.path.read_bytes()
                before_changes = self.store._connection.total_changes
                inspection = self._inspect(
                    BrokerQualificationInspectionRequest(
                        run_id=request.run_id,
                        stage_ordinal=request.stage_ordinal,
                        challenge=bytes([index]) * 32,
                    )
                )
                self.assertEqual(inspection.state, state)
                self.assertEqual(inspection.stage_snapshot["state"], durable_state)
                self.assertEqual(inspection.dispatch is not None, state == "terminal")
                self.assertEqual(self.path.read_bytes(), before_bytes)
                self.assertEqual(self.store._connection.total_changes, before_changes)

        self.store.mark_ltfs_qualification_dispatched(prepared)
        observations = ((prepared, "dispatched", "DISPATCHED"),)
        for index, (request, state, durable_state) in enumerate(observations, 3):
            with self.subTest(state=state):
                before_bytes = self.path.read_bytes()
                before_changes = self.store._connection.total_changes
                inspection = self._inspect(
                    BrokerQualificationInspectionRequest(
                        run_id=request.run_id,
                        stage_ordinal=request.stage_ordinal,
                        challenge=bytes([index]) * 32,
                    )
                )
                self.assertEqual(inspection.state, state)
                self.assertEqual(inspection.stage_snapshot["state"], durable_state)
                self.assertEqual(inspection.dispatch is not None, state == "terminal")
                self.assertEqual(self.path.read_bytes(), before_bytes)
                self.assertEqual(self.store._connection.total_changes, before_changes)

        self.store.fence_ltfs_qualification(prepared)
        before_bytes = self.path.read_bytes()
        before_changes = self.store._connection.total_changes
        inspection = self._inspect(
            BrokerQualificationInspectionRequest(
                run_id=prepared.run_id,
                stage_ordinal=prepared.stage_ordinal,
                challenge=b"f" * 32,
            )
        )
        self.assertEqual(inspection.state, "fenced")
        self.assertEqual(inspection.stage_snapshot["state"], "FENCED")
        self.assertIsNone(inspection.dispatch)
        self.assertEqual(self.path.read_bytes(), before_bytes)
        self.assertEqual(self.store._connection.total_changes, before_changes)

        before_bytes = self.path.read_bytes()
        before_changes = self.store._connection.total_changes
        missing = self._inspect(
            BrokerQualificationInspectionRequest(
                run_id=prepared.run_id, stage_ordinal=8, challenge=b"m" * 32
            )
        )
        self.assertEqual(missing.state, "missing")
        self.assertIsNone(missing.stage_snapshot)
        self.assertIsNone(missing.dispatch)
        self.assertEqual(self.path.read_bytes(), before_bytes)
        self.assertEqual(self.store._connection.total_changes, before_changes)
        self.assertEqual(self.driver.requests, [terminal])

    def test_inspection_after_terminal_response_loss_and_store_restart_is_read_only(
        self,
    ):
        request = request_model(operation=QualificationOperation.FORMAT)
        self.assertEqual(request.protocol_version, 2)
        self.assertEqual(request.expected_mam_medium_serial, "CURRENT-SERIAL")
        client_socket, service_socket = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET
        )
        packet = encode_request(
            "execute_ltfs_qualification_stage",
            request_id=b"r" * 32,
            capability=CAPABILITY,
            params={"request": request},
        )
        worker = threading.Thread(
            target=self.service.handle_connection, args=(service_socket,)
        )
        client_socket.send(packet)
        client_socket.shutdown(socket.SHUT_RD)
        worker.start()
        worker.join(timeout=2)
        client_socket.close()
        service_socket.close()
        self.assertFalse(worker.is_alive())
        self.assertEqual(
            self.store.ltfs_qualification_stage(
                request.run_id, request.stage_ordinal
            ).state,
            "TERMINAL",
        )
        self.assertEqual(self.driver.requests, [request])

        self.store.close()
        self.store = _open_store(self.path)
        self.addCleanup(self.store.close)
        self.service = CommandBrokerService(
            self.store,
            object(),
            capability=CAPABILITY,
            proof_key=PROOF_KEY,
            daemon_uid=os.getuid(),
            daemon_gid=os.getgid(),
            enforcing=False,
            daemon_context="system_u:system_r:lto_archiver_t:s0",
        )
        before_bytes = self.path.read_bytes()
        before_changes = self.store._connection.total_changes
        inspection = self._inspect(
            BrokerQualificationInspectionRequest(
                run_id=request.run_id,
                stage_ordinal=request.stage_ordinal,
                challenge=b"r" * 32,
            )
        )
        self.assertEqual(inspection.state, "terminal")
        self.assertIsNotNone(inspection.dispatch)
        self.assertEqual(inspection.dispatch.request_sha256, request.request_sha256)
        self.assertEqual(self.path.read_bytes(), before_bytes)
        self.assertEqual(self.store._connection.total_changes, before_changes)

    def test_client_rejects_substituted_broker_proof(self):
        request = request_model()
        valid = self._execute(request)
        client_socket, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(peer.close)
        client = UnixBrokeredCgroupScopeApi.from_connected_socket(
            client_socket,
            BrokeredCgroupScopeToken(CAPABILITY),
            expected_peer_uid=os.getuid(),
        )
        with (
            patch.object(
                client,
                "_exchange",
                return_value={"dispatch": replace(valid, broker_proof=b"x" * 32)},
            ),
            self.assertRaises(BrokerUnavailable),
        ):
            client.execute_ltfs_qualification_stage(request)

    def test_client_rejects_substituted_inspection_proof_and_challenge(self):
        request = request_model()
        inspection_request = BrokerQualificationInspectionRequest(
            run_id=request.run_id,
            stage_ordinal=request.stage_ordinal,
            challenge=b"i" * 32,
        )
        valid = self._inspect(inspection_request)
        client_socket, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(peer.close)
        client = UnixBrokeredCgroupScopeApi.from_connected_socket(
            client_socket,
            BrokeredCgroupScopeToken(CAPABILITY),
            expected_peer_uid=os.getuid(),
        )
        for candidate_request, candidate_inspection in (
            (inspection_request, replace(valid, proof=b"x" * 32)),
            (
                replace(inspection_request, challenge=b"j" * 32),
                valid,
            ),
        ):
            with (
                self.subTest(challenge=candidate_request.challenge),
                patch.object(
                    client,
                    "_exchange",
                    return_value={"inspection": candidate_inspection},
                ),
                self.assertRaises(BrokerUnavailable),
            ):
                client.inspect_ltfs_qualification_stage(candidate_request)

    def test_client_rejects_terminal_dispatch_proof_even_with_a_valid_inspection_proof(
        self,
    ):
        request = request_model()
        self._execute(request)
        inspection_request = BrokerQualificationInspectionRequest(
            run_id=request.run_id,
            stage_ordinal=request.stage_ordinal,
            challenge=b"i" * 32,
        )
        valid = self._inspect(inspection_request)
        assert valid.dispatch is not None
        unsigned = replace(
            valid,
            dispatch=replace(valid.dispatch, broker_proof=b"x" * 32),
            proof=b"\0" * 32,
        )
        substituted = replace(
            unsigned,
            proof=hmac.new(
                CAPABILITY,
                qualification_inspection_proof_payload(inspection_request, unsigned),
                hashlib.sha256,
            ).digest(),
        )
        client_socket, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(peer.close)
        client = UnixBrokeredCgroupScopeApi.from_connected_socket(
            client_socket,
            BrokeredCgroupScopeToken(CAPABILITY),
            expected_peer_uid=os.getuid(),
        )
        with (
            patch.object(client, "_exchange", return_value={"inspection": substituted}),
            self.assertRaises(BrokerUnavailable),
        ):
            client.inspect_ltfs_qualification_stage(inspection_request)

    def test_client_generates_the_inspection_challenge(self):
        client_socket, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(peer.close)
        client = UnixBrokeredCgroupScopeApi.from_connected_socket(
            client_socket,
            BrokeredCgroupScopeToken(CAPABILITY),
            expected_peer_uid=os.getuid(),
        )
        self.addCleanup(client._discard_connected_socket)
        observed = []

        def exchange(method, params):
            self.assertEqual(method, "inspect_ltfs_qualification_stage")
            request = params["request"]
            observed.append(request)
            unsigned = BrokerQualificationInspection(
                state="missing",
                stage_snapshot=None,
                dispatch=None,
                observation_nonce=b"o" * 32,
                proof=b"\0" * 32,
            )
            return {
                "inspection": replace(
                    unsigned,
                    proof=hmac.new(
                        CAPABILITY,
                        qualification_inspection_proof_payload(request, unsigned),
                        hashlib.sha256,
                    ).digest(),
                )
            }

        with (
            patch(
                "ltobackup.broker.client.secrets.token_bytes", return_value=b"c" * 32
            ),
            patch.object(client, "_exchange", side_effect=exchange),
        ):
            result = client.inspect_ltfs_qualification_stage(
                "11111111-1111-4111-8111-111111111111", 3
            )
        self.assertEqual(result.state, "missing")
        self.assertEqual(observed[0].challenge, b"c" * 32)

    def test_post_dispatch_failure_is_fenced_and_never_retried(self):
        request = request_model()
        self.driver.fail = True
        with self.assertRaises(BrokerUnavailable):
            self._execute(request)
        record = self.store.ltfs_qualification_stage(
            request.run_id, request.stage_ordinal
        )
        self.assertIsNotNone(record)
        self.assertEqual(record.state, "FENCED")

        self.driver.fail = False
        with self.assertRaises(BrokerUnavailable):
            self._execute(request)
        self.assertEqual(self.driver.requests, [request])

    def _assert_ltfs_boundary_fences_before_driver_call(self, boundary):
        request = request_model(stage_ordinal=21, request_nonce=b"u" * 32)
        if boundary == "active":
            self.service._active_ltfs = object()
        else:
            self.service._finalizing_monitors = 1
        try:
            with self.assertRaises(BrokerUnavailable):
                self._execute(request)
        finally:
            self.service._active_ltfs = None
            self.service._finalizing_monitors = 0
        record = self.store.ltfs_qualification_stage(
            request.run_id, request.stage_ordinal
        )
        self.assertIsNotNone(record)
        self.assertEqual(record.state, "FENCED")
        self.assertEqual(self.driver.requests, [])

    def test_active_ltfs_session_fences_before_driver_call(self):
        self._assert_ltfs_boundary_fences_before_driver_call("active")

    def test_finalizing_ltfs_session_fences_before_driver_call(self):
        self._assert_ltfs_boundary_fences_before_driver_call("finalizing")

    def test_same_stage_with_new_nonce_is_substitution_not_retry(self):
        request = request_model()
        self._execute(request)
        with self.assertRaises(BrokerUnavailable):
            self._execute(replace(request, request_nonce=b"z" * 32))
        self.assertEqual(self.driver.requests, [request])

    def test_closed_executor_maps_every_operation_without_command_inputs(self):
        driver = _QualificationExecutor()
        executor = BrokerQualificationExecutor(
            driver,
            credential=QUALIFICATION_CREDENTIAL,
            now_ns=lambda: QUALIFICATION_NOW_NS,
        )
        for ordinal, operation in enumerate(SUPPORTED_OPERATIONS, 1):
            request = request_model(
                stage_ordinal=ordinal,
                operation=operation,
                request_nonce=bytes([ordinal]) * 32,
            )
            result = executor.execute(request)
            self.assertIsInstance(result, BrokerQualificationExecution)
        self.assertEqual(
            [request.operation for request in driver.requests],
            list(SUPPORTED_OPERATIONS),
        )

    def test_invalid_operation_token_is_rejected_before_driver_dispatch(self):
        driver = _QualificationExecutor()
        executor = BrokerQualificationExecutor(
            driver,
            credential=QUALIFICATION_CREDENTIAL,
            now_ns=lambda: QUALIFICATION_NOW_NS,
        )
        with self.assertRaises(ValueError):
            executor.execute(request_model(operation_token="0" * 64))
        self.assertEqual(driver.requests, [])

    def test_operation_token_rejects_every_exact_target_substitution(self):
        original = request_model()
        mutations = (
            {"run_id": "22222222-2222-4222-8222-222222222222"},
            {"plan_sha256": "b" * 64},
            {"stage_ordinal": original.stage_ordinal + 1},
            {"operation": QualificationOperation.FORMAT},
            {"tape_device_identity_sha256": "3" * 64},
            {"scsi_device_identity_sha256": "4" * 64},
            {"expected_media_scope_sha256": "5" * 64},
            {"observed_media_identity_sha256": "6" * 64},
            {"expected_physical_label": r"SUBSTITUTED/LABEL\EXACT"},
            {"expected_tape_serial": "SUBSTITUTED-SERIAL"},
            {"expected_drive_serial": "SUBSTITUTED-DRIVE"},
            {"expected_drive_wwid": "0x5000000000000002"},
            {"expected_volume_uuid": "33333333-3333-4333-8333-333333333333"},
            {"expected_generation": original.expected_generation + 1},
            {"issued_at_ns": original.issued_at_ns + 1},
            {"expires_at_ns": original.expires_at_ns - 1},
            {"request_nonce": b"z" * 32},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                driver = _QualificationExecutor()
                executor = BrokerQualificationExecutor(
                    driver,
                    credential=QUALIFICATION_CREDENTIAL,
                    now_ns=lambda: QUALIFICATION_NOW_NS,
                )
                with self.assertRaises(ValueError):
                    executor.execute(replace(original, **mutation))
                self.assertEqual(driver.requests, [])

    def test_expired_plan_authorization_is_rejected_before_dispatch(self):
        plan = QualificationPlan(
            schema=1,
            run_id="11111111-1111-4111-8111-111111111111",
            job_id="job-current",
            cassette_sequence=4,
            physical_label=r"CURRENT/LABEL\EXACT",
            tape_serial="CURRENT-SERIAL",
            drive_serial="DRIVE-SERIAL",
            drive_wwid="DRIVE-WWID",
            linux_tree_sha256="7" * 64,
            ltfs_tree_sha256="8" * 64,
            ltfs_rpm_sha256="9" * 64,
            issued_at_ns=0,
            expires_at_ns=1,
            operations=(QualificationOperation.WIPE,),
        )
        request = request_model(
            plan_sha256=plan.plan_sha256,
            issued_at_ns=plan.issued_at_ns,
            expires_at_ns=plan.expires_at_ns,
            operation_token=plan.authorize(
                QualificationOperation.WIPE, QUALIFICATION_CREDENTIAL
            ),
        )
        driver = _QualificationExecutor()
        executor = BrokerQualificationExecutor(
            driver,
            credential=QUALIFICATION_CREDENTIAL,
            now_ns=lambda: 2,
        )
        with self.assertRaises(ValueError):
            executor.execute(request)
        self.assertEqual(driver.requests, [])

    def test_concurrent_exact_request_dispatches_driver_once(self):
        request = request_model()
        barrier = threading.Barrier(2)
        original_mark = self.store.mark_ltfs_qualification_dispatched

        def synchronized_mark(candidate):
            barrier.wait(timeout=2)
            return original_mark(candidate)

        results = []
        errors = []

        def invoke():
            try:
                results.append(self._execute(request))
            except BrokerUnavailable as error:
                errors.append(error)

        with patch.object(
            self.store,
            "mark_ltfs_qualification_dispatched",
            side_effect=synchronized_mark,
        ):
            workers = [threading.Thread(target=invoke) for _index in range(2)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=4)

        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(self.driver.requests, [request])


if __name__ == "__main__":
    unittest.main()
