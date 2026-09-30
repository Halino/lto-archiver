"""Fail-closed orchestration for label-bound physical LTFS qualification."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

from ltobackup.catalog import Catalog
from ltobackup.errors import CatalogError, ValidationError

from .plan import (
    SUPPORTED_QUALIFICATION_OPERATIONS,
    QualificationOperation,
    QualificationPlan,
    QualificationRefused,
    qualification_success_exit_codes,
)

_EXECUTION_ORDER = (
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
_CONTENT_OPERATIONS = frozenset(
    {
        QualificationOperation.READ_ONLY,
        QualificationOperation.ADDITIVE_WRITE,
        QualificationOperation.OVERWRITE,
        QualificationOperation.REPAIR,
    }
)
_REQUEST_DOMAIN = b"lto-archiver/ltfs-qualification-request/v1\x00"


class QualificationFenced(RuntimeError):
    """The run requires manual evidence review and must never auto-retry."""


@dataclass(frozen=True, slots=True)
class QualificationObservation:
    physical_label: str
    tape_serial: str
    drive_serial: str
    drive_wwid: str
    volume_uuid: str | None
    index_generation: int | None

    def __post_init__(self) -> None:
        for value, purpose in (
            (self.physical_label, "physical label"),
            (self.tape_serial, "tape serial"),
            (self.drive_serial, "drive serial"),
            (self.drive_wwid, "drive WWID"),
        ):
            if (
                type(value) is not str
                or not value
                or len(value.encode("utf-8")) > 255
                or any(
                    ord(character) < 32 or ord(character) == 127 for character in value
                )
            ):
                raise QualificationRefused(f"observed {purpose} is invalid")
        if (self.volume_uuid is None) != (self.index_generation is None):
            raise QualificationRefused("observed LTFS media state is incomplete")
        if self.volume_uuid is not None:
            try:
                parsed = uuid.UUID(self.volume_uuid)
            except (AttributeError, TypeError, ValueError):
                raise QualificationRefused(
                    "observed LTFS volume UUID is invalid"
                ) from None
            if str(parsed) != self.volume_uuid:
                raise QualificationRefused("observed LTFS volume UUID is invalid")
            if (
                type(self.index_generation) is not int
                or not 0 <= self.index_generation < 1 << 64
            ):
                raise QualificationRefused("observed LTFS generation is invalid")


@dataclass(frozen=True, slots=True)
class QualificationExecution:
    terminal_receipt_sha256: str
    child_exit_code: int
    content_manifest_sha256: str | None

    def __post_init__(self) -> None:
        _digest(self.terminal_receipt_sha256, "terminal receipt")
        if type(self.child_exit_code) is not int:
            raise QualificationRefused("qualification child exit code is invalid")
        if self.content_manifest_sha256 is not None:
            _digest(self.content_manifest_sha256, "content manifest")


class QualificationExecutor(Protocol):
    def observe(self) -> QualificationObservation: ...

    def execute(
        self,
        operation: QualificationOperation,
        *,
        plan: QualificationPlan,
        request_sha256: str,
    ) -> QualificationExecution: ...


class QualificationRunner:
    def __init__(
        self,
        *,
        catalog: Catalog,
        plan: QualificationPlan,
        credential: bytes,
        executor: QualificationExecutor,
        now_ns: Callable[[], int],
    ) -> None:
        if type(catalog) is not Catalog or type(plan) is not QualificationPlan:
            raise QualificationRefused("qualification runner inputs are invalid")
        if type(credential) is not bytes or len(credential) != 32:
            raise QualificationRefused("qualification credential is invalid")
        if not callable(now_ns):
            raise QualificationRefused("qualification clock is invalid")
        self._catalog = catalog
        self._plan = plan
        self._credential = credential
        self._executor = executor
        self._now_ns = now_ns

    def run(self, tokens: Mapping[QualificationOperation, str]) -> None:
        if any(
            operation not in SUPPORTED_QUALIFICATION_OPERATIONS
            for operation in self._plan.operations
        ):
            raise QualificationRefused("qualification operation is unsupported")
        if type(tokens) is not dict or set(tokens) != set(self._plan.operations):
            raise QualificationRefused("qualification token set is not exact")
        now = self._now_ns()
        for operation in self._plan.operations:
            self._plan.verify_token(
                operation, tokens[operation], self._credential, now_ns=now
            )
        self._catalog.create_ltfs_qualification_run(self._plan)
        ordinal = 1
        for operation in _EXECUTION_ORDER:
            if operation not in self._plan.operations:
                continue
            token = tokens[operation]
            request_sha256 = self._request_sha256(operation, token)
            before = self._observe_exact(operation, request_sha256, ordinal)
            self._catalog.record_ltfs_qualification_stage(
                run_id=self._plan.run_id,
                ordinal=ordinal,
                operation=operation,
                request_sha256=request_sha256,
                dispatched=True,
                terminal_receipt_sha256=None,
                child_exit_code=None,
                before_volume_uuid=before.volume_uuid,
                before_generation=before.index_generation,
                after_volume_uuid=None,
                after_generation=None,
                content_manifest_sha256=None,
                verdict="dispatch_started",
            )
            ordinal += 1
            try:
                execution = self._executor.execute(
                    operation,
                    plan=self._plan,
                    request_sha256=request_sha256,
                )
                self._validate_execution(operation, execution)
                after = self._exact_observation(self._executor.observe())
                self._catalog.record_ltfs_qualification_stage(
                    run_id=self._plan.run_id,
                    ordinal=ordinal,
                    operation=operation,
                    request_sha256=request_sha256,
                    dispatched=True,
                    terminal_receipt_sha256=execution.terminal_receipt_sha256,
                    child_exit_code=execution.child_exit_code,
                    before_volume_uuid=before.volume_uuid,
                    before_generation=before.index_generation,
                    after_volume_uuid=after.volume_uuid,
                    after_generation=after.index_generation,
                    content_manifest_sha256=execution.content_manifest_sha256,
                    verdict="pass",
                )
            except Exception as exc:
                self._fence("ambiguous_or_invalid_terminal_evidence")
                raise QualificationFenced(
                    "LTFS qualification dispatch is ambiguous and has been fenced"
                ) from exc
            ordinal += 1
        self._catalog.complete_ltfs_qualification_run(self._plan.run_id)

    def _observe_exact(
        self, operation: QualificationOperation, request_sha256: str, ordinal: int
    ) -> QualificationObservation:
        try:
            return self._exact_observation(self._executor.observe())
        except Exception as exc:
            try:
                self._catalog.record_ltfs_qualification_stage(
                    run_id=self._plan.run_id,
                    ordinal=ordinal,
                    operation=operation,
                    request_sha256=request_sha256,
                    dispatched=False,
                    terminal_receipt_sha256=None,
                    child_exit_code=None,
                    before_volume_uuid=None,
                    before_generation=None,
                    after_volume_uuid=None,
                    after_generation=None,
                    content_manifest_sha256=None,
                    verdict="pre_dispatch_refused",
                )
            finally:
                self._fence("pre_dispatch_identity_mismatch")
            raise QualificationFenced(
                "LTFS qualification identity mismatch before dispatch"
            ) from exc

    def _exact_observation(self, value: object) -> QualificationObservation:
        if type(value) is not QualificationObservation:
            raise QualificationRefused("qualification observation is invalid")
        if (
            value.physical_label != self._plan.physical_label
            or value.tape_serial != self._plan.tape_serial
            or value.drive_serial != self._plan.drive_serial
            or value.drive_wwid != self._plan.drive_wwid
        ):
            raise QualificationRefused("qualification identity does not match the plan")
        return value

    @staticmethod
    def _validate_execution(
        operation: QualificationOperation, execution: object
    ) -> None:
        if type(execution) is not QualificationExecution:
            raise QualificationRefused("qualification terminal result is invalid")
        accepted = qualification_success_exit_codes(operation)
        if execution.child_exit_code not in accepted:
            raise QualificationRefused("qualification command did not succeed")
        if operation in _CONTENT_OPERATIONS:
            if execution.content_manifest_sha256 is None:
                raise QualificationRefused("qualification content proof is missing")
        elif execution.content_manifest_sha256 is not None:
            raise QualificationRefused("qualification content proof is unexpected")

    def _request_sha256(self, operation: QualificationOperation, token: str) -> str:
        payload = json.dumps(
            {
                "operation": operation.value,
                "plan_sha256": self._plan.plan_sha256,
                "run_id": self._plan.run_id,
                "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return hashlib.sha256(_REQUEST_DOMAIN + payload).hexdigest()

    def _fence(self, reason: str) -> None:
        try:
            self._catalog.fence_ltfs_qualification_run(self._plan.run_id, reason)
        except (CatalogError, ValidationError, sqlite3.DatabaseError):
            raise QualificationFenced(
                "LTFS qualification evidence could not be fenced durably"
            ) from None


def _digest(value: object, purpose: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise QualificationRefused(f"qualification {purpose} digest is invalid")
    return value
