"""A fixed-window rate limiter.

Deliberately simple and deliberately in-process, with the consequences
stated rather than hidden: with N replicas the effective limit is N times the
configured one, and a window boundary allows a burst of up to twice the limit
across it. Both are acceptable for protecting a query engine from a runaway
script and neither is acceptable as an abuse control, which belongs at the
edge.

The counter is bounded. An unbounded dict keyed on caller identity is a
memory leak that an attacker chooses the size of, so entries are evicted
once the window passes and the map is capped.
"""
from __future__ import annotations

import threading
import time

MAX_TRACKED_IDENTIFIERS = 10_000


class RateLimiter:
    def __init__(self, *, per_minute: int = 120, window_seconds: int = 60):
        if per_minute < 1:
            raise ValueError('per_minute must be at least 1')
        self.per_minute = per_minute
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._counts: dict[str, tuple[int, int]] = {}

    def _window(self, now: float | None = None) -> int:
        return int((time.time() if now is None else now) // self.window_seconds)

    def allow(self, identifier: str, *, now: float | None = None) -> bool:
        window = self._window(now)
        with self._lock:
            if len(self._counts) > MAX_TRACKED_IDENTIFIERS:
                # Drop everything from older windows rather than growing.
                self._counts = {k: v for k, v in self._counts.items()
                                if v[0] == window}
                if len(self._counts) > MAX_TRACKED_IDENTIFIERS:
                    self._counts.clear()
            stored_window, count = self._counts.get(identifier, (window, 0))
            if stored_window != window:
                stored_window, count = window, 0
            if count >= self.per_minute:
                self._counts[identifier] = (stored_window, count)
                return False
            self._counts[identifier] = (stored_window, count + 1)
            return True

    def remaining(self, identifier: str, *, now: float | None = None) -> int:
        window = self._window(now)
        with self._lock:
            stored_window, count = self._counts.get(identifier, (window, 0))
            if stored_window != window:
                return self.per_minute
            return max(0, self.per_minute - count)

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()
