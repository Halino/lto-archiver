from __future__ import annotations

import hmac
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable, Mapping
from typing import Any

_SAFE_AUDIT_KEYS = frozenset(
    {
        "action",
        "count",
        "credential_generation",
        "enabled",
        "remote_address",
        "request_id",
        "result",
        "role",
        "state",
    }
)


def constant_time_matches(expected: str, supplied: str) -> bool:
    """Compare secret-derived ASCII values without content-dependent branching."""

    return hmac.compare_digest(expected.encode("utf-8"), supplied.encode("utf-8"))


def sanitize_audit_payload(value: Any) -> Any:
    """Return a JSON-compatible copy with credential-bearing fields omitted."""

    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            if key.casefold() not in _SAFE_AUDIT_KEYS:
                continue
            sanitized[key] = sanitize_audit_payload(item)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [sanitize_audit_payload(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return None


class LoginRateLimiter:
    """Bound failed logins independently by normalized user and network origin."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_failures: int = 5,
        window_seconds: float = 300,
    ) -> None:
        if max_failures < 1:
            raise ValueError("max_failures must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._clock = clock
        self._max_failures = max_failures
        self._window_seconds = window_seconds
        self._failures: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    @staticmethod
    def _keys(login_name: str, origin: str) -> tuple[tuple[str, str], ...]:
        return (("user", login_name.strip().casefold()), ("origin", origin.strip()))

    def _prune(self, key: tuple[str, str], now: float) -> None:
        failures = self._failures.get(key)
        if failures is None:
            return
        cutoff = now - self._window_seconds
        while failures and failures[0] <= cutoff:
            failures.popleft()
        if not failures:
            self._failures.pop(key, None)

    def allowed(self, login_name: str, origin: str) -> bool:
        now = self._clock()
        keys = self._keys(login_name, origin)
        with self._lock:
            for key in keys:
                self._prune(key, now)
            return all(
                len(self._failures.get(key, ())) < self._max_failures for key in keys
            )

    def record_failure(self, login_name: str, origin: str) -> None:
        now = self._clock()
        keys = self._keys(login_name, origin)
        with self._lock:
            for key in keys:
                self._prune(key, now)
                self._failures[key].append(now)

    def record_success(self, login_name: str, origin: str) -> None:
        """Clear the user's failures while retaining origin-wide spray evidence."""

        del origin
        key = ("user", login_name.strip().casefold())
        with self._lock:
            self._failures.pop(key, None)


class ReauthenticationRateLimiter(LoginRateLimiter):
    """Separate limiter namespace for recent-password verification attempts."""

    @staticmethod
    def _keys(login_name: str, origin: str) -> tuple[tuple[str, str], ...]:
        del origin
        return (("session", login_name.strip().casefold()),)

    def record_success(self, login_name: str, origin: str) -> None:
        del origin
        key = ("session", login_name.strip().casefold())
        with self._lock:
            self._failures.pop(key, None)
