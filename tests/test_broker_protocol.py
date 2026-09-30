from __future__ import annotations

import base64
import hashlib
import hmac
import json
import unittest

from ltobackup.broker.ltfs_session import derive_receipt_operation_uuid
from ltobackup.broker.protocol import (
    BrokerProtocolError,
    BrokerRequest,
    BrokerResponse,
    LtfsProtocolAuthority,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
    ltfs_request_sha256,
    readiness_capability_payload,
)
from ltobackup.qualification.broker_models import BrokerQualificationInspectionRequest
from ltobackup.tape.command_supervisor import (
    BrokeredCgroupScopeReceipt,
    LtfsFinalizationReceipt,
    LtfsSessionReceipt,
    LtfsSessionRequest,
    LtfsStandaloneReceipt,
)


def _receipt() -> dict[str, object]:
    return {
        "protocol_version": 1,
        "command_id": "command-17",
        "owner_generation": 9,
        "request_nonce": b"r" * 32,
        "scope_id": "scope-17",
        "scope_path_sha256": "a" * 64,
        "broker_nonce": b"n" * 32,
        "broker_proof": b"p" * 32,
        "recursive_population": True,
        "recursive_members": True,
        "cgroup_kill": True,
    }


def _permit() -> dict[str, object]:
    return {
        "protocol_version": 1,
        "receipt": _receipt(),
        "pid": 4711,
        "request_nonce": b"q" * 32,
        "permit_nonce": b"m" * 32,
        "broker_proof": b"z" * 32,
    }


def _scope_receipt_model() -> BrokeredCgroupScopeReceipt:
    return BrokeredCgroupScopeReceipt(**_receipt())


def _ltfs_request() -> LtfsSessionRequest:
    return LtfsSessionRequest(
        protocol_version=1,
        operation_id="operation-11111111111141118111111111111111",
        owner_generation=9,
        mount_path_sha256="1" * 64,
        tape_device_identity_sha256="2" * 64,
        scsi_device_identity_sha256="3" * 64,
        expected_media_scope_sha256="4" * 64,
        observed_media_identity_sha256="5" * 64,
        expected_volume_uuid="22222222-2222-4222-8222-222222222222",
        expected_prior_generation=7,
        read_only=False,
        tape_fd_identity_sha256="6" * 64,
        scsi_fd_identity_sha256="7" * 64,
        cgroup_scope_receipt=_scope_receipt_model(),
        request_nonce=b"l" * 32,
    )


def _ltfs_receipt() -> LtfsSessionReceipt:
    request = _ltfs_request()
    request_sha256 = ltfs_request_sha256(request)
    return LtfsSessionReceipt(
        protocol_version=1,
        operation_id="operation-11111111111141118111111111111111",
        receipt_operation_uuid=derive_receipt_operation_uuid(
            operation_id=request.operation_id,
            owner_generation=request.owner_generation,
            request_sha256=request_sha256,
        ),
        observed_volume_uuid="22222222-2222-4222-8222-222222222222",
        observed_prior_generation=7,
        read_only=False,
        owner_generation=9,
        request_nonce=b"l" * 32,
        session_id="session-17",
        request_sha256=request_sha256,
        child_pid=4711,
        child_start_ticks=8822,
        mount_namespace_sha256="9" * 64,
        broker_nonce=b"b" * 32,
        broker_proof=b"e" * 32,
        mounted=True,
        observed_volume_label="TEST VOLUME",
        observed_media_identity_sha256=request.observed_media_identity_sha256,
    )


def _ltfs_authority() -> LtfsProtocolAuthority:
    request = _ltfs_request()
    return LtfsProtocolAuthority(
        operation_id=request.operation_id,
        owner_generation=request.owner_generation,
        cgroup_scope_receipt=request.cgroup_scope_receipt,
        tape_fd_identity_sha256=request.tape_fd_identity_sha256,
        scsi_fd_identity_sha256=request.scsi_fd_identity_sha256,
    )


def _readiness_result() -> dict[str, object]:
    features: dict[str, object] = {
        "broker_state": True,
        "delegated_cgroup": True,
        "recursive_population": True,
        "cgroup_kill": True,
        "ltfs_session_contract": 1,
        "challenge": b"n" * 32,
        "reconciliation_nonce": b"r" * 32,
        "ltfs_tool_identity_sha256": "8" * 64,
        "fusermount_tool_identity_sha256": "9" * 64,
        "reconciliation_clean": True,
    }
    features["capability_proof"] = hmac.new(
        b"c" * 32,
        _readiness_payload(features),
        hashlib.sha256,
    ).digest()
    return {"nonce": b"n" * 32, "features": features}


def _readiness_payload(features: dict[str, object]) -> bytes:
    fields = {
        key: value for key, value in features.items() if key != "capability_proof"
    }
    canonical = {
        key: (
            {"base64": base64.b64encode(value).decode("ascii")}
            if type(value) is bytes
            else value
        )
        for key, value in fields.items()
    }
    return json.dumps(
        {
            "domain": "readiness-capability-proof-v1",
            "fields": canonical,
            "version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _pending_start_authority() -> tuple[LtfsProtocolAuthority, BrokerRequest]:
    request = _ltfs_request()
    authority = _ltfs_authority()
    decoded = decode_request(
        encode_request(
            "start_ltfs_session",
            request_id=b"i" * 32,
            capability=b"c" * 32,
            params={"request": request},
        ),
        ltfs_authority=authority,
        ancillary_fd_identities=(
            request.tape_fd_identity_sha256,
            request.scsi_fd_identity_sha256,
        ),
    )
    return authority, decoded


def _started_authority() -> tuple[LtfsProtocolAuthority, BrokerRequest]:
    authority, decoded = _pending_start_authority()
    decode_response(
        encode_response(
            "start_ltfs_session",
            request_id=b"i" * 32,
            result={"receipt": _ltfs_receipt()},
        ),
        request=decoded,
        ltfs_authority=authority,
    )
    return authority, decoded


def _pending_observe_authority(
    *, challenge: bytes = b"h" * 32
) -> tuple[LtfsProtocolAuthority, BrokerRequest]:
    authority, _ = _started_authority()
    receipt = _ltfs_receipt()
    request = decode_request(
        encode_request(
            "observe_ltfs_session",
            request_id=b"j" * 32,
            capability=b"c" * 32,
            params={
                "operation_id": receipt.operation_id,
                "owner_generation": receipt.owner_generation,
                "receipt": receipt,
                "challenge": challenge,
            },
        ),
        ltfs_authority=authority,
    )
    return authority, request


def _pending_finalize_authority(
    *, request_nonce: bytes = b"f" * 32
) -> tuple[LtfsProtocolAuthority, BrokerRequest]:
    authority, _ = _started_authority()
    receipt = _ltfs_receipt()
    request = decode_request(
        encode_request(
            "finalize_ltfs_session",
            request_id=b"k" * 32,
            capability=b"c" * 32,
            params={
                "operation_id": receipt.operation_id,
                "owner_generation": receipt.owner_generation,
                "receipt": receipt,
                "request_nonce": request_nonce,
            },
        ),
        ltfs_authority=authority,
    )
    return authority, request


def _ltfs_finalization() -> LtfsFinalizationReceipt:
    session_receipt = _ltfs_receipt()
    terminal_fields = {
        "schema": 1,
        "stage": "terminal",
        "operation_id": session_receipt.receipt_operation_uuid,
        "volume_uuid": "22222222-2222-4222-8222-222222222222",
        "prior_generation": 7,
        "new_generation": 8,
        "bytes_valid": True,
        "bytes": 1234,
        "files_valid": True,
        "files": 4,
        "phase_duration_ns": [0] * 11,
        "capture_duration_ns": 0,
        "device_close_duration_ns": 0,
        "device_close_result_valid": True,
        "device_close_result": 0,
        "catalog_ack_duration_ns": 0,
        "media_committed": True,
        "catalog_acknowledged": True,
        "cleanup_failed": False,
        "result": 0,
    }
    terminal_sha256 = hashlib.sha256(
        (json.dumps(terminal_fields, separators=(",", ":")) + "\n").encode("ascii")
    ).hexdigest()
    try:
        return LtfsFinalizationReceipt(
            protocol_version=1,
            session_receipt=session_receipt,
            standalone_receipt=LtfsStandaloneReceipt(
                schema=1,
                stage="terminal",
                operation_id=session_receipt.receipt_operation_uuid,
                volume_uuid="22222222-2222-4222-8222-222222222222",
                prior_generation=7,
                new_generation=8,
                bytes_valid=True,
                bytes=1234,
                files_valid=True,
                files=4,
                phase_duration_ns=(0,) * 11,
                capture_duration_ns=0,
                device_close_duration_ns=0,
                device_close_result_valid=True,
                device_close_result=0,
                catalog_ack_duration_ns=0,
                media_committed=True,
                catalog_acknowledged=True,
                cleanup_failed=False,
                result=0,
                terminal_sha256=terminal_sha256,
            ),
            request_nonce=b"f" * 32,
            finalization_nonce=b"z" * 32,
            broker_proof=b"q" * 32,
            unmounted=True,
            child_quiesced=True,
        )
    except TypeError as error:
        raise AssertionError("finalization omits the standalone receipt") from error


class BrokerProtocolTests(unittest.TestCase):
    request_id = b"i" * 32
    capability = b"c" * 32

    def test_inspection_method_is_a_closed_protocol_member(self):
        request = BrokerQualificationInspectionRequest(
            run_id="11111111-1111-4111-8111-111111111111",
            stage_ordinal=3,
            challenge=b"h" * 32,
        )
        packet = encode_request(
            "inspect_ltfs_qualification_stage",
            request_id=self.request_id,
            capability=self.capability,
            params={"request": request},
        )
        self.assertEqual(
            decode_request(packet).params,
            {"request": request},
        )
        for challenge in (b"short", b"h" * 33):
            with self.subTest(challenge=challenge), self.assertRaises(ValueError):
                BrokerQualificationInspectionRequest(
                    run_id=request.run_id,
                    stage_ordinal=request.stage_ordinal,
                    challenge=challenge,
                )

    def test_ltfs_session_methods_and_receipts_are_exact_and_canonical(self):
        authority = _ltfs_authority()
        request_cases = {
            "start_ltfs_session": {"request": _ltfs_request()},
            "observe_ltfs_session": {
                "operation_id": "operation-11111111111141118111111111111111",
                "owner_generation": 9,
                "receipt": _ltfs_receipt(),
                "challenge": b"h" * 32,
            },
            "finalize_ltfs_session": {
                "operation_id": "operation-11111111111141118111111111111111",
                "owner_generation": 9,
                "receipt": _ltfs_receipt(),
                "request_nonce": b"f" * 32,
            },
        }
        result_cases = {
            "start_ltfs_session": {"receipt": _ltfs_receipt()},
            "observe_ltfs_session": {
                "receipt": _ltfs_receipt(),
                "challenge": b"h" * 32,
                "observation_nonce": b"o" * 32,
                "broker_proof": b"v" * 32,
                "mounted": True,
            },
            "finalize_ltfs_session": {"receipt": _ltfs_finalization()},
        }

        for method, params in request_cases.items():
            with self.subTest(method=method):
                encoded = encode_request(
                    method,
                    request_id=self.request_id,
                    capability=self.capability,
                    params=params,
                )
                ancillary = (
                    (
                        _ltfs_request().tape_fd_identity_sha256,
                        _ltfs_request().scsi_fd_identity_sha256,
                    )
                    if method == "start_ltfs_session"
                    else ()
                )
                decoded_request = decode_request(
                    encoded,
                    ltfs_authority=authority,
                    ancillary_fd_identities=ancillary,
                )
                self.assertEqual(decoded_request.params, params)
                with self.assertRaises(BrokerProtocolError):
                    encode_request(
                        method,
                        request_id=self.request_id,
                        capability=self.capability,
                        params={**params, "argv": ["/usr/bin/ltfs"]},
                    )

                response = encode_response(
                    method,
                    request_id=self.request_id,
                    result=result_cases[method],
                )
                self.assertEqual(
                    decode_response(
                        response,
                        request=decoded_request,
                        ltfs_authority=authority,
                    ).result,
                    result_cases[method],
                )

    def test_ltfs_session_authority_rejects_replay_swapped_fds_and_stale_scope(self):
        request = _ltfs_request()
        packet = encode_request(
            "start_ltfs_session",
            request_id=self.request_id,
            capability=self.capability,
            params={"request": request},
        )
        authority = _ltfs_authority()
        exact_fds = (
            request.tape_fd_identity_sha256,
            request.scsi_fd_identity_sha256,
        )
        decoded = decode_request(
            packet,
            ltfs_authority=authority,
            ancillary_fd_identities=exact_fds,
        )
        self.assertEqual(decoded.params, {"request": request})
        with self.assertRaises(BrokerProtocolError):
            decode_request(packet)
        for fds in ((), exact_fds[:1], (*exact_fds, "8" * 64), exact_fds[::-1]):
            with self.subTest(fds=fds), self.assertRaises(BrokerProtocolError):
                decode_request(
                    packet,
                    ltfs_authority=_ltfs_authority(),
                    ancillary_fd_identities=fds,
                )
        with self.assertRaises(BrokerProtocolError):
            decode_request(
                packet,
                ltfs_authority=authority,
                ancillary_fd_identities=exact_fds,
            )

        for mutation in (
            {"operation_id": "operation-stale"},
            {"owner_generation": 8},
            {
                "cgroup_scope_receipt": request.cgroup_scope_receipt.__class__(
                    **{
                        **request.cgroup_scope_receipt.__dict__,
                        "command_id": "unrelated-command",
                    }
                )
            },
        ):
            mutated = request.__class__(**{**request.__dict__, **mutation})
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(BrokerProtocolError),
            ):
                decode_request(
                    encode_request(
                        "start_ltfs_session",
                        request_id=self.request_id,
                        capability=self.capability,
                        params={"request": mutated},
                    ),
                    ltfs_authority=_ltfs_authority(),
                    ancillary_fd_identities=exact_fds,
                )

    def test_ltfs_session_responses_are_causally_bound_and_opaque_values_unique(self):
        request = _ltfs_request()
        authority = _ltfs_authority()
        start = decode_request(
            encode_request(
                "start_ltfs_session",
                request_id=self.request_id,
                capability=self.capability,
                params={"request": request},
            ),
            ltfs_authority=authority,
            ancillary_fd_identities=(
                request.tape_fd_identity_sha256,
                request.scsi_fd_identity_sha256,
            ),
        )
        receipt = _ltfs_receipt()
        start_payload = encode_response(
            "start_ltfs_session",
            request_id=self.request_id,
            result={"receipt": receipt},
        )
        self.assertEqual(
            decode_response(
                start_payload, request=start, ltfs_authority=authority
            ).result,
            {"receipt": receipt},
        )
        with self.assertRaises(BrokerProtocolError):
            decode_response(
                start_payload,
                request=start,
                ltfs_authority=authority,
            )

        for mutation in (
            {"operation_id": "other-operation"},
            {"owner_generation": 10},
            {"request_nonce": b"x" * 32},
            {"request_sha256": "8" * 64},
            {"broker_nonce": receipt.request_nonce},
            {"broker_proof": receipt.broker_nonce},
        ):
            bad = receipt.__class__(**{**receipt.__dict__, **mutation})
            pending_authority, pending_start = _pending_start_authority()
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(BrokerProtocolError),
            ):
                decode_response(
                    encode_response(
                        "start_ltfs_session",
                        request_id=self.request_id,
                        result={"receipt": bad},
                    ),
                    request=pending_start,
                    ltfs_authority=pending_authority,
                )

        observe = decode_request(
            encode_request(
                "observe_ltfs_session",
                request_id=b"j" * 32,
                capability=self.capability,
                params={
                    "operation_id": receipt.operation_id,
                    "owner_generation": receipt.owner_generation,
                    "receipt": receipt,
                    "challenge": b"h" * 32,
                },
            ),
            ltfs_authority=authority,
        )
        valid_observation = {
            "receipt": receipt,
            "challenge": b"h" * 32,
            "observation_nonce": b"o" * 32,
            "broker_proof": b"v" * 32,
            "mounted": True,
        }
        self.assertIsNotNone(
            decode_response(
                encode_response(
                    "observe_ltfs_session",
                    request_id=b"j" * 32,
                    result=valid_observation,
                ),
                request=observe,
                ltfs_authority=authority,
            ).result
        )
        fresh_authority, _ = _started_authority()
        wrong_challenge_request = decode_request(
            encode_request(
                "observe_ltfs_session",
                request_id=b"m" * 32,
                capability=self.capability,
                params={
                    "operation_id": receipt.operation_id,
                    "owner_generation": receipt.owner_generation,
                    "receipt": receipt,
                    "challenge": b"w" * 32,
                },
            ),
            ltfs_authority=fresh_authority,
        )
        with self.assertRaises(BrokerProtocolError):
            decode_response(
                encode_response(
                    "observe_ltfs_session",
                    request_id=b"m" * 32,
                    result=valid_observation,
                ),
                request=wrong_challenge_request,
                ltfs_authority=fresh_authority,
            )
        for field in ("observation_nonce", "broker_proof"):
            pending_authority, pending_observe = _pending_observe_authority()
            with self.subTest(field=field), self.assertRaises(BrokerProtocolError):
                decode_response(
                    encode_response(
                        "observe_ltfs_session",
                        request_id=b"j" * 32,
                        result={**valid_observation, field: b"h" * 32},
                    ),
                    request=pending_observe,
                    ltfs_authority=pending_authority,
                )

        finalize = decode_request(
            encode_request(
                "finalize_ltfs_session",
                request_id=b"k" * 32,
                capability=self.capability,
                params={
                    "operation_id": receipt.operation_id,
                    "owner_generation": receipt.owner_generation,
                    "receipt": receipt,
                    "request_nonce": b"f" * 32,
                },
            ),
            ltfs_authority=authority,
        )
        finalization = _ltfs_finalization()
        self.assertIsNotNone(
            decode_response(
                encode_response(
                    "finalize_ltfs_session",
                    request_id=b"k" * 32,
                    result={"receipt": finalization},
                ),
                request=finalize,
                ltfs_authority=authority,
            ).result
        )
        fresh_authority, _ = _started_authority()
        wrong_nonce_request = decode_request(
            encode_request(
                "finalize_ltfs_session",
                request_id=b"n" * 32,
                capability=self.capability,
                params={
                    "operation_id": receipt.operation_id,
                    "owner_generation": receipt.owner_generation,
                    "receipt": receipt,
                    "request_nonce": b"w" * 32,
                },
            ),
            ltfs_authority=fresh_authority,
        )
        with self.assertRaises(BrokerProtocolError):
            decode_response(
                encode_response(
                    "finalize_ltfs_session",
                    request_id=b"n" * 32,
                    result={"receipt": finalization},
                ),
                request=wrong_nonce_request,
                ltfs_authority=fresh_authority,
            )
        for field in ("finalization_nonce", "broker_proof"):
            pending_authority, pending_finalize = _pending_finalize_authority()
            bad = finalization.__class__(
                **{**finalization.__dict__, field: finalization.request_nonce}
            )
            with self.subTest(field=field), self.assertRaises(BrokerProtocolError):
                decode_response(
                    encode_response(
                        "finalize_ltfs_session",
                        request_id=b"k" * 32,
                        result={"receipt": bad},
                    ),
                    request=pending_finalize,
                    ltfs_authority=pending_authority,
                )

    def test_ltfs_session_rejects_tampered_digests_and_receipt_reuse(self):
        request = _ltfs_request()
        for field, value in (
            ("mount_path_sha256", "A" * 64),
            ("tape_fd_identity_sha256", "6" * 63),
            ("owner_generation", True),
            ("read_only", 0),
            ("request_nonce", b"short"),
        ):
            with self.subTest(field=field), self.assertRaises(BrokerProtocolError):
                encode_request(
                    "start_ltfs_session",
                    request_id=self.request_id,
                    capability=self.capability,
                    params={
                        "request": request.__class__(
                            **{**request.__dict__, field: value}
                        )
                    },
                )

        receipt = _ltfs_receipt()
        with self.assertRaises(BrokerProtocolError):
            encode_request(
                "finalize_ltfs_session",
                request_id=self.request_id,
                capability=self.capability,
                params={
                    "operation_id": "11111111-1111-4111-8111-111111111111",
                    "owner_generation": 9,
                    "receipt": receipt.__class__(
                        **{**receipt.__dict__, "owner_generation": 10}
                    ),
                    "request_nonce": b"f" * 32,
                },
            )

    def test_ltfs_session_lifecycle_is_single_pending_and_terminal(self):
        authority, pending_start = _pending_start_authority()
        request = _ltfs_request()
        second_start = request.__class__(
            **{**request.__dict__, "request_nonce": b"x" * 32}
        )
        with self.assertRaises(BrokerProtocolError):
            decode_request(
                encode_request(
                    "start_ltfs_session",
                    request_id=b"x" * 32,
                    capability=self.capability,
                    params={"request": second_start},
                ),
                ltfs_authority=authority,
                ancillary_fd_identities=(
                    request.tape_fd_identity_sha256,
                    request.scsi_fd_identity_sha256,
                ),
            )

        decode_response(
            encode_response(
                "start_ltfs_session",
                request_id=pending_start.request_id,
                result={"receipt": _ltfs_receipt()},
            ),
            request=pending_start,
            ltfs_authority=authority,
        )
        finalize = decode_request(
            encode_request(
                "finalize_ltfs_session",
                request_id=b"k" * 32,
                capability=self.capability,
                params={
                    "operation_id": request.operation_id,
                    "owner_generation": request.owner_generation,
                    "receipt": _ltfs_receipt(),
                    "request_nonce": b"f" * 32,
                },
            ),
            ltfs_authority=authority,
        )
        for method, request_id, params in (
            (
                "observe_ltfs_session",
                b"o" * 32,
                {
                    "operation_id": request.operation_id,
                    "owner_generation": request.owner_generation,
                    "receipt": _ltfs_receipt(),
                    "challenge": b"h" * 32,
                },
            ),
            (
                "finalize_ltfs_session",
                b"n" * 32,
                {
                    "operation_id": request.operation_id,
                    "owner_generation": request.owner_generation,
                    "receipt": _ltfs_receipt(),
                    "request_nonce": b"g" * 32,
                },
            ),
        ):
            with self.subTest(method=method), self.assertRaises(BrokerProtocolError):
                decode_request(
                    encode_request(
                        method,
                        request_id=request_id,
                        capability=self.capability,
                        params=params,
                    ),
                    ltfs_authority=authority,
                )

        decode_response(
            encode_response(
                "finalize_ltfs_session",
                request_id=finalize.request_id,
                result={"receipt": _ltfs_finalization()},
            ),
            request=finalize,
            ltfs_authority=authority,
        )
        for method, params in (
            (
                "observe_ltfs_session",
                {
                    "operation_id": request.operation_id,
                    "owner_generation": request.owner_generation,
                    "receipt": _ltfs_receipt(),
                    "challenge": b"u" * 32,
                },
            ),
            (
                "finalize_ltfs_session",
                {
                    "operation_id": request.operation_id,
                    "owner_generation": request.owner_generation,
                    "receipt": _ltfs_receipt(),
                    "request_nonce": b"v" * 32,
                },
            ),
        ):
            with (
                self.subTest(terminal_method=method),
                self.assertRaises(BrokerProtocolError),
            ):
                decode_request(
                    encode_request(
                        method,
                        request_id=b"t" * 32,
                        capability=self.capability,
                        params=params,
                    ),
                    ltfs_authority=authority,
                )

    def test_ltfs_error_responses_are_causal_and_release_pending_state(self):
        authority, pending = _pending_start_authority()
        payload = encode_response(
            "start_ltfs_session",
            request_id=pending.request_id,
            error_code="scope.conflict",
        )
        with self.assertRaises(BrokerProtocolError):
            decode_response(payload)
        with self.assertRaises(BrokerProtocolError):
            decode_response(
                encode_response(
                    "start_ltfs_session",
                    request_id=b"w" * 32,
                    error_code="scope.conflict",
                ),
                request=pending,
                ltfs_authority=authority,
            )
        with self.assertRaises(BrokerProtocolError):
            decode_response(
                encode_response(
                    "create_scope",
                    request_id=pending.request_id,
                    error_code="scope.conflict",
                ),
                request=pending,
                ltfs_authority=authority,
            )
        response = decode_response(
            payload,
            request=pending,
            ltfs_authority=authority,
        )
        self.assertEqual(response.error_code, "scope.conflict")

        retry = _ltfs_request().__class__(
            **{**_ltfs_request().__dict__, "request_nonce": b"x" * 32}
        )
        decode_request(
            encode_request(
                "start_ltfs_session",
                request_id=b"w" * 32,
                capability=self.capability,
                params={"request": retry},
            ),
            ltfs_authority=authority,
            ancillary_fd_identities=(
                retry.tape_fd_identity_sha256,
                retry.scsi_fd_identity_sha256,
            ),
        )

    def test_ltfs_authority_rejects_colliding_cgroup_receipt_opaque_values(self):
        request = _ltfs_request()
        collision = request.cgroup_scope_receipt.request_nonce
        receipt = request.cgroup_scope_receipt.__class__(
            **{
                **request.cgroup_scope_receipt.__dict__,
                "broker_nonce": collision,
                "broker_proof": collision,
            }
        )
        with self.assertRaises(BrokerProtocolError):
            LtfsProtocolAuthority(
                operation_id=request.operation_id,
                owner_generation=request.owner_generation,
                cgroup_scope_receipt=receipt,
                tape_fd_identity_sha256=request.tape_fd_identity_sha256,
                scsi_fd_identity_sha256=request.scsi_fd_identity_sha256,
            )

    def test_ltfs_request_ids_are_one_shot_across_error_retries(self):
        receipt = _ltfs_receipt()
        cases = (
            (
                _pending_start_authority,
                "start_ltfs_session",
                lambda pending: {
                    "request": _ltfs_request().__class__(
                        **{**_ltfs_request().__dict__, "request_nonce": b"x" * 32}
                    )
                },
                (
                    _ltfs_request().tape_fd_identity_sha256,
                    _ltfs_request().scsi_fd_identity_sha256,
                ),
            ),
            (
                _pending_observe_authority,
                "observe_ltfs_session",
                lambda pending: {
                    "operation_id": receipt.operation_id,
                    "owner_generation": receipt.owner_generation,
                    "receipt": receipt,
                    "challenge": b"x" * 32,
                },
                (),
            ),
            (
                _pending_finalize_authority,
                "finalize_ltfs_session",
                lambda pending: {
                    "operation_id": receipt.operation_id,
                    "owner_generation": receipt.owner_generation,
                    "receipt": receipt,
                    "request_nonce": b"x" * 32,
                },
                (),
            ),
        )
        for factory, method, params_factory, ancillary in cases:
            with self.subTest(method=method):
                authority, pending = factory()
                decode_response(
                    encode_response(
                        method,
                        request_id=pending.request_id,
                        error_code="scope.conflict",
                    ),
                    request=pending,
                    ltfs_authority=authority,
                )
                with self.assertRaises(BrokerProtocolError):
                    decode_request(
                        encode_request(
                            method,
                            request_id=pending.request_id,
                            capability=self.capability,
                            params=params_factory(pending),
                        ),
                        ltfs_authority=authority,
                        ancillary_fd_identities=ancillary,
                    )

    def test_request_round_trip_is_canonical_and_restores_opaque_values(self):
        encoded = encode_request(
            "create_scope",
            request_id=self.request_id,
            capability=self.capability,
            params={
                "command_id": "command-17",
                "owner_generation": 9,
                "request_nonce": b"r" * 32,
            },
        )

        self.assertEqual(
            encoded,
            encode_request(
                "create_scope",
                request_id=self.request_id,
                capability=self.capability,
                params={
                    "request_nonce": b"r" * 32,
                    "owner_generation": 9,
                    "command_id": "command-17",
                },
            ),
        )
        self.assertNotIn(b" ", encoded)
        self.assertEqual(
            decode_request(encoded),
            BrokerRequest(
                method="create_scope",
                request_id=self.request_id,
                capability=self.capability,
                params={
                    "command_id": "command-17",
                    "owner_generation": 9,
                    "request_nonce": b"r" * 32,
                },
            ),
        )

    def test_all_request_method_shapes_are_closed(self):
        cases = {
            "create_scope": {
                "command_id": "command-17",
                "owner_generation": 9,
                "request_nonce": b"r" * 32,
            },
            "open_scope": {
                "command_id": "command-17",
                "owner_generation": 9,
                "request_nonce": b"r" * 32,
            },
            "attach": {"receipt": _receipt(), "pid": 4711},
            "validate_scope": {"receipt": _receipt(), "challenge": b"h" * 32},
            "prepare_release": {
                "receipt": _receipt(),
                "pid": 4711,
                "request_nonce": b"q" * 32,
            },
            "release_child": {
                "receipt": _receipt(),
                "permit": _permit(),
                "pid": 4711,
            },
            "claim_unreleased": {
                "receipt": _receipt(),
                "pid": 4711,
                "permit_sha256": "b" * 64,
                "challenge": b"h" * 32,
            },
            "signal_scope": {"receipt": _receipt(), "signum": 15},
            "kill_scope": {"receipt": _receipt()},
            "release_scope": {"receipt": _receipt()},
        }

        for method, params in cases.items():
            with self.subTest(method=method):
                decoded = decode_request(
                    encode_request(
                        method,
                        request_id=self.request_id,
                        capability=self.capability,
                        params=params,
                    )
                )
                self.assertEqual(decoded.method, method)
                self.assertEqual(decoded.params, params)
                with self.assertRaises(BrokerProtocolError):
                    encode_request(
                        method,
                        request_id=self.request_id,
                        capability=self.capability,
                        params={**params, "extra": 0},
                    )

    def test_decode_rejects_duplicate_unknown_and_missing_fields(self):
        token = base64.b64encode(self.capability).decode("ascii")
        request_id = base64.b64encode(self.request_id).decode("ascii")
        nonce = base64.b64encode(b"r" * 32).decode("ascii")
        payloads = (
            (
                f'{{"capability":"{token}","method":"open_scope","params":{{}},'
                f'"request_id":"{request_id}","version":1,"version":1}}'
            ),
            (
                f'{{"capability":"{token}","extra":0,"method":"open_scope",'
                f'"params":{{}},"request_id":"{request_id}","version":1}}'
            ),
            (
                f'{{"capability":"{token}","method":"open_scope","params":'
                '{"command_id":"command-17","owner_generation":9},'
                f'"request_id":"{request_id}","version":1}}'
            ),
            (
                f'{{"capability":"{token}","method":"open_scope","params":'
                '{"command_id":"command-17","command_id":"other",'
                f'"owner_generation":9,"request_nonce":"{nonce}"}},'
                f'"request_id":"{request_id}","version":1}}'
            ),
        )
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaises(BrokerProtocolError):
                decode_request(payload.encode("ascii"))

    def test_decode_rejects_wrong_exact_types(self):
        valid = json.loads(
            encode_request(
                "create_scope",
                request_id=self.request_id,
                capability=self.capability,
                params={
                    "command_id": "command-17",
                    "owner_generation": 9,
                    "request_nonce": b"r" * 32,
                },
            )
        )
        mutations = (
            ("version", True),
            ("method", 7),
            ("params", []),
            ("request_id", None),
        )
        for field, value in mutations:
            malformed = {**valid, field: value}
            with (
                self.subTest(field=field, value=value),
                self.assertRaises(BrokerProtocolError),
            ):
                decode_request(json.dumps(malformed).encode("ascii"))
        for value in (True, 9.0, "9"):
            malformed = dict(valid)
            malformed["params"] = {**valid["params"], "owner_generation": value}
            with (
                self.subTest(owner_generation=value),
                self.assertRaises(BrokerProtocolError),
            ):
                decode_request(json.dumps(malformed).encode("ascii"))

    def test_identity_fields_reject_non_ascii_controls_and_path_separators(self):
        for command_id in ("comandò", "command\n17", "command/17", "command\\17", ""):
            with (
                self.subTest(command_id=command_id),
                self.assertRaises(BrokerProtocolError),
            ):
                encode_request(
                    "create_scope",
                    request_id=self.request_id,
                    capability=self.capability,
                    params={
                        "command_id": command_id,
                        "owner_generation": 9,
                        "request_nonce": b"r" * 32,
                    },
                )

    def test_decode_rejects_noncanonical_or_invalid_base64_and_hex(self):
        raw = json.loads(
            encode_request(
                "claim_unreleased",
                request_id=self.request_id,
                capability=self.capability,
                params={
                    "receipt": _receipt(),
                    "pid": 4711,
                    "permit_sha256": "b" * 64,
                    "challenge": b"h" * 32,
                },
            )
        )
        mutations = (
            ("request_id", "!invalid!"),
            ("capability", base64.b64encode(b"short").decode("ascii")),
        )
        for field, value in mutations:
            malformed = {**raw, field: value}
            with self.subTest(field=field), self.assertRaises(BrokerProtocolError):
                decode_request(json.dumps(malformed).encode("ascii"))
        malformed = dict(raw)
        malformed["params"] = {**raw["params"], "permit_sha256": "B" * 64}
        with self.assertRaises(BrokerProtocolError):
            decode_request(json.dumps(malformed).encode("ascii"))

    def test_packets_over_limit_are_rejected_in_both_directions(self):
        with self.assertRaises(BrokerProtocolError):
            decode_request(b"{" + b" " * 65_536)
        with self.assertRaises(BrokerProtocolError):
            decode_response(b"{" + b" " * 65_536)

    def test_decode_rejects_noncanonical_json_and_oversized_integer_fields(self):
        canonical = encode_request(
            "create_scope",
            request_id=self.request_id,
            capability=self.capability,
            params={
                "command_id": "command-17",
                "owner_generation": 9,
                "request_nonce": b"r" * 32,
            },
        )
        noncanonical = canonical.replace(b'":', b'": ', 1)
        with self.assertRaises(BrokerProtocolError):
            decode_request(noncanonical)

        for method, params in (
            (
                "create_scope",
                {
                    "command_id": "command-17",
                    "owner_generation": 1 << 63,
                    "request_nonce": b"r" * 32,
                },
            ),
            ("attach", {"receipt": _receipt(), "pid": 1 << 31}),
        ):
            with self.subTest(method=method), self.assertRaises(BrokerProtocolError):
                encode_request(
                    method,
                    request_id=self.request_id,
                    capability=self.capability,
                    params=params,
                )

    def test_success_and_error_response_shapes_are_closed(self):
        result = {"receipt": _receipt()}
        encoded = encode_response(
            "create_scope", request_id=self.request_id, result=result
        )
        self.assertEqual(
            decode_response(encoded),
            BrokerResponse(
                method="create_scope",
                request_id=self.request_id,
                result=result,
                error_code=None,
            ),
        )
        error = encode_response(
            "create_scope",
            request_id=self.request_id,
            error_code="scope.conflict",
        )
        self.assertEqual(
            decode_response(error),
            BrokerResponse(
                method="create_scope",
                request_id=self.request_id,
                result=None,
                error_code="scope.conflict",
            ),
        )

        raw = json.loads(encoded)
        for malformed in (
            {**raw, "extra": 0},
            {**raw, "status": "unknown"},
            {**raw, "method": "unknown"},
            {**raw, "result": {"receipt": {**raw["result"]["receipt"], "extra": 0}}},
        ):
            with (
                self.subTest(malformed=malformed),
                self.assertRaises(BrokerProtocolError),
            ):
                decode_response(json.dumps(malformed).encode("ascii"))

    def test_readiness_response_is_exact_and_proof_payload_is_canonical(self):
        result = _readiness_result()
        encoded = encode_response(
            "readiness", request_id=self.request_id, result=result
        )
        self.assertEqual(decode_response(encoded).result, result)
        expected_payload = (
            b'{"domain":"readiness-capability-proof-v1","fields":'
            b'{"broker_state":true,"cgroup_kill":true,'
            b'"challenge":{"base64":"bm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm4="},'
            b'"delegated_cgroup":true,'
            b'"fusermount_tool_identity_sha256":"9999999999999999999999999999999999999999999999999999999999999999",'
            b'"ltfs_session_contract":1,'
            b'"ltfs_tool_identity_sha256":"8888888888888888888888888888888888888888888888888888888888888888",'
            b'"reconciliation_clean":true,'
            b'"reconciliation_nonce":{"base64":"cnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnI="},'
            b'"recursive_population":true},"version":1}'
        )
        self.assertEqual(_readiness_payload(result["features"]), expected_payload)
        self.assertEqual(
            readiness_capability_payload(
                {
                    key: value
                    for key, value in result["features"].items()
                    if key != "capability_proof"
                }
            ),
            expected_payload,
        )

        raw = json.loads(encoded)
        features = raw["result"]["features"]
        malformed = (
            {**raw, "result": {**raw["result"], "nonce": "c2hvcnQ="}},
            {
                **raw,
                "result": {
                    **raw["result"],
                    "features": {**features, "legacy_extra": True},
                },
            },
            {
                **raw,
                "result": {
                    **raw["result"],
                    "features": {
                        key: value
                        for key, value in features.items()
                        if key != "reconciliation_clean"
                    },
                },
            },
            {
                **raw,
                "result": {
                    **raw["result"],
                    "features": {
                        **features,
                        "challenge": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=",
                    },
                },
            },
        )
        for candidate in malformed:
            with (
                self.subTest(candidate=candidate),
                self.assertRaises(BrokerProtocolError),
            ):
                decode_response(
                    json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode(
                        "ascii"
                    )
                )

    def test_response_rejects_unknown_error_code_or_mismatched_result_shape(self):
        with self.assertRaises(BrokerProtocolError):
            encode_response(
                "attach", request_id=self.request_id, error_code="raw.exception"
            )
        with self.assertRaises(BrokerProtocolError):
            encode_response(
                "attach", request_id=self.request_id, result={"unexpected": True}
            )


if __name__ == "__main__":
    unittest.main()
