from __future__ import annotations

import json
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock

from ..catalog import Catalog


@dataclass(frozen=True)
class ServerEvent:
    id: int
    event_type: str
    _payload_json: bytes

    @property
    def payload(self) -> dict:
        """Return a detached view; callers cannot mutate retained memory."""

        value = json.loads(self._payload_json)
        if not isinstance(value, dict):  # Defensive: retained events are objects.
            raise TypeError("retained event payload is invalid")
        return value


class EventBus:
    """Process-local replay window with catalog-durable event numbering."""

    def __init__(
        self,
        catalog_factory: Callable[[], Catalog],
        *,
        retention: int = 2_000,
        max_event_bytes: int = 64 * 1024,
        max_retained_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        if (
            isinstance(retention, bool)
            or not isinstance(retention, int)
            or retention <= 0
        ):
            raise ValueError("event retention must be a positive integer")
        if (
            isinstance(max_event_bytes, bool)
            or not isinstance(max_event_bytes, int)
            or max_event_bytes <= 0
        ):
            raise ValueError("maximum event payload bytes must be a positive integer")
        if (
            isinstance(max_retained_bytes, bool)
            or not isinstance(max_retained_bytes, int)
            or max_retained_bytes < max_event_bytes
        ):
            raise ValueError("retained event bytes must cover one event payload")
        self._catalog_factory = catalog_factory
        # Do not give deque a maxlen: automatic eviction would bypass the
        # matching retained-byte accounting below.
        self._events: deque[ServerEvent] = deque()
        self._retention = retention
        self._lock = RLock()
        self._closed = False
        self._max_event_bytes = max_event_bytes
        self._max_retained_bytes = max_retained_bytes
        self._retained_bytes = 0

    def publish(self, event_type: str, payload: dict) -> ServerEvent:
        if not isinstance(event_type, str) or not event_type:
            raise ValueError("event type is required")
        if not isinstance(payload, dict):
            raise TypeError("event payload must be a dictionary")
        with self._lock:
            self._require_open()
            return self._publish_locked(event_type, payload)

    def replay(
        self,
        after_id: int | None,
        snapshot: Callable[[], dict],
    ) -> tuple[ServerEvent, ...]:
        # A daemon status snapshot crosses into the service (and from there
        # diagnostics).  Never invoke it while the event lock is held: a
        # telemetry publisher takes the inverse path.  Retry if an event was
        # published while composing the snapshot so the replacement cursor
        # never claims to include an event it predates.
        while True:
            with self._lock:
                self._require_open()
                current_id = self._latest_reserved_event_id_locked()
                if not self._requires_snapshot_locked(after_id, current_id):
                    return self._replay_locked(after_id, current_id)

            payload = snapshot()
            safe_payload, payload_bytes = self._bounded_payload(payload)

            with self._lock:
                self._require_open()
                if self._latest_reserved_event_id_locked() != current_id:
                    continue
                return (
                    self._publish_normalized_locked(
                        "state.replace", safe_payload, payload_bytes
                    ),
                )

    def close(self) -> None:
        with self._lock:
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("event bus is closed")

    def _latest_reserved_event_id_locked(self) -> int:
        with self._catalog_factory() as catalog:
            return catalog.latest_reserved_event_id()

    def _requires_snapshot_locked(self, after_id: int | None, current_id: int) -> bool:
        if after_id is None:
            return True
        if isinstance(after_id, bool) or not isinstance(after_id, int) or after_id < 0:
            return True
        if after_id > current_id:
            return True
        if after_id == current_id:
            return False
        if not self._events:
            return True
        if after_id < self._events[0].id - 1:
            return True
        replayed = tuple(event for event in self._events if event.id > after_id)
        expected_ids = tuple(range(after_id + 1, current_id + 1))
        return tuple(event.id for event in replayed) != expected_ids

    def _replay_locked(
        self, after_id: int | None, current_id: int
    ) -> tuple[ServerEvent, ...]:
        if after_id == current_id:
            return ()
        assert isinstance(after_id, int)
        return tuple(event for event in self._events if event.id > after_id)

    def _publish_locked(self, event_type: str, payload: dict) -> ServerEvent:
        safe_payload, payload_bytes = self._bounded_payload(payload)
        return self._publish_normalized_locked(event_type, safe_payload, payload_bytes)

    def _publish_normalized_locked(
        self,
        event_type: str,
        safe_payload: dict,
        payload_bytes: int,
    ) -> ServerEvent:
        compact_previous = (
            event_type == "state.patch"
            and bool(self._events)
            and self._events[-1].event_type == event_type
        )
        if compact_previous:
            merged_payload = dict(self._events[-1].payload)
            merged_payload.update(safe_payload)
            safe_payload, payload_bytes = self._bounded_payload(merged_payload)
        with self._catalog_factory() as catalog:
            event_id = catalog.reserve_event_id()
        if event_type == "state.replace":
            self._events.clear()
            self._retained_bytes = 0
        elif compact_previous:
            previous = self._events.pop()
            self._retained_bytes -= self._payload_size(previous.payload)
        while self._events and (
            len(self._events) >= self._retention
            or self._retained_bytes + payload_bytes > self._max_retained_bytes
        ):
            previous = self._events.popleft()
            self._retained_bytes -= self._payload_size(previous.payload)
        event = ServerEvent(
            event_id,
            event_type,
            self._canonical_payload(safe_payload),
        )
        self._events.append(event)
        self._retained_bytes += payload_bytes
        return event

    def _bounded_payload(self, payload: dict) -> tuple[dict, int]:
        try:
            encoded = json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        except (TypeError, ValueError) as exc:
            raise TypeError("event payload must be JSON-safe") from exc
        if len(encoded) > self._max_event_bytes:
            raise ValueError("event payload exceeds memory bound")
        decoded = json.loads(encoded)
        if not isinstance(decoded, dict):  # Defensive: JSON object is required.
            raise TypeError("event payload must be a JSON object")
        return decoded, len(encoded)

    @staticmethod
    def _payload_size(payload: dict) -> int:
        return len(EventBus._canonical_payload(payload))

    @staticmethod
    def _canonical_payload(payload: dict) -> bytes:
        return json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
