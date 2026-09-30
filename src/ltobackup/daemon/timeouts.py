from __future__ import annotations

from math import isfinite
from threading import TIMEOUT_MAX


def validate_shutdown_timeout(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or value < 0
        or value > TIMEOUT_MAX
        or not isfinite(value)
    ):
        raise ValueError(
            "shutdown timeout must be between 0 and threading.TIMEOUT_MAX seconds"
        )
    return float(value)
