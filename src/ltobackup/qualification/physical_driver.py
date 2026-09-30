"""Closed adapter between broker qualification requests and physical LTFS runtime."""

from __future__ import annotations

import uuid
from pathlib import Path

from .broker_models import BrokerQualificationExecution, BrokerQualificationRequest
from .plan import QualificationOperation, QualificationRefused


class PhysicalLtfsQualificationDriver:
    """Expose one fixed method per destructive-qualification operation.

    The runtime receives only a validated typed request.  Labels and tape serials
    remain identity evidence and are never converted into filesystem names.
    """

    def __init__(self, *, runtime: object) -> None:
        if not callable(getattr(runtime, "execute", None)):
            raise TypeError("invalid physical LTFS qualification runtime")
        self._runtime = runtime

    @staticmethod
    def stage_workspace(root: Path, request: BrokerQualificationRequest) -> Path:
        if not isinstance(root, Path) or not root.is_absolute():
            raise QualificationRefused("qualification workspace root is invalid")
        if type(request) is not BrokerQualificationRequest:
            raise QualificationRefused("exact broker qualification request required")
        parsed_run_id = uuid.UUID(request.run_id)
        if parsed_run_id.version != 4 or str(parsed_run_id) != request.run_id:
            raise QualificationRefused("qualification run id is invalid")
        return (
            root
            / request.run_id
            / f"{request.stage_ordinal:04d}-{request.operation.value}"
        )

    def _execute(
        self,
        operation: QualificationOperation,
        request: BrokerQualificationRequest,
    ) -> BrokerQualificationExecution:
        if type(request) is not BrokerQualificationRequest:
            raise QualificationRefused("exact broker qualification request required")
        if request.operation is not operation:
            raise QualificationRefused("qualification operation dispatch mismatch")
        result = self._runtime.execute(operation, request)
        if type(result) is not BrokerQualificationExecution:
            raise QualificationRefused("physical LTFS qualification result is invalid")
        return result

    def read_only(
        self, request: BrokerQualificationRequest
    ) -> BrokerQualificationExecution:
        return self._execute(QualificationOperation.READ_ONLY, request)

    def additive_write(
        self, request: BrokerQualificationRequest
    ) -> BrokerQualificationExecution:
        return self._execute(QualificationOperation.ADDITIVE_WRITE, request)

    def format(
        self, request: BrokerQualificationRequest
    ) -> BrokerQualificationExecution:
        return self._execute(QualificationOperation.FORMAT, request)

    def overwrite(
        self, request: BrokerQualificationRequest
    ) -> BrokerQualificationExecution:
        return self._execute(QualificationOperation.OVERWRITE, request)

    def repair(
        self, request: BrokerQualificationRequest
    ) -> BrokerQualificationExecution:
        return self._execute(QualificationOperation.REPAIR, request)

    def wipe(self, request: BrokerQualificationRequest) -> BrokerQualificationExecution:
        return self._execute(QualificationOperation.WIPE, request)

    def unload(
        self, request: BrokerQualificationRequest
    ) -> BrokerQualificationExecution:
        return self._execute(QualificationOperation.UNLOAD, request)

    def load(self, request: BrokerQualificationRequest) -> BrokerQualificationExecution:
        return self._execute(QualificationOperation.LOAD, request)

    def eject(
        self, request: BrokerQualificationRequest
    ) -> BrokerQualificationExecution:
        return self._execute(QualificationOperation.EJECT, request)
