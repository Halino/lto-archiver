"""Closed broker-side operation dispatch for physical LTFS qualification."""

from __future__ import annotations

import hmac
import time
from collections.abc import Callable

from .broker_models import (
    BrokerQualificationExecution,
    BrokerQualificationRequest,
    qualification_request_operation_token,
    qualification_success_exit_codes,
)
from .plan import (
    QualificationOperation,
    QualificationRefused,
)

_METHODS = {
    QualificationOperation.READ_ONLY: "read_only",
    QualificationOperation.ADDITIVE_WRITE: "additive_write",
    QualificationOperation.FORMAT: "format",
    QualificationOperation.OVERWRITE: "overwrite",
    QualificationOperation.REPAIR: "repair",
    QualificationOperation.WIPE: "wipe",
    QualificationOperation.UNLOAD: "unload",
    QualificationOperation.LOAD: "load",
    QualificationOperation.EJECT: "eject",
}


class BrokerQualificationExecutor:
    """Select one fixed local implementation from the closed operation enum.

    The authenticated request supplies identity evidence and an operation token,
    never an executable, path, mountpoint, option, or free-form command.
    """

    def __init__(
        self,
        driver: object,
        *,
        credential: bytes,
        now_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        if type(credential) is not bytes or len(credential) != 32:
            raise ValueError("invalid LTFS qualification credential")
        if driver is None or any(
            not callable(getattr(driver, method, None)) for method in _METHODS.values()
        ):
            raise ValueError("incomplete LTFS qualification driver")
        if not callable(now_ns):
            raise TypeError("invalid LTFS qualification clock")
        self._driver = driver
        self._credential = credential
        self._now_ns = now_ns

    def execute(
        self, request: BrokerQualificationRequest
    ) -> BrokerQualificationExecution:
        if type(request) is not BrokerQualificationRequest:
            raise QualificationRefused("exact broker qualification request required")
        current_time = self._now_ns()
        if (
            type(current_time) is not int
            or current_time < request.issued_at_ns
            or current_time > request.expires_at_ns
        ):
            raise QualificationRefused("LTFS qualification authorization is expired")
        expected_token = qualification_request_operation_token(
            request, self._credential
        )
        if not hmac.compare_digest(request.operation_token, expected_token):
            raise QualificationRefused("LTFS qualification token is invalid")
        method_name = _METHODS.get(request.operation)
        if method_name is None:
            raise QualificationRefused(
                "LTFS qualification operation is not allowlisted"
            )
        result = getattr(self._driver, method_name)(request)
        if type(result) is not BrokerQualificationExecution:
            raise QualificationRefused("LTFS qualification result is invalid")
        accepted = qualification_success_exit_codes(request.operation)
        if result.child_exit_code not in accepted:
            raise QualificationRefused("LTFS qualification command failed")
        return result
