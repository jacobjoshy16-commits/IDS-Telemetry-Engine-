"""Bounded, event-time sliding windows used by stateful detectors."""

from __future__ import annotations

from bisect import bisect_right
from collections import OrderedDict, deque
from collections.abc import Hashable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Generic, TypeVar

K = TypeVar("K", bound=Hashable)
T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class TimedValue(Generic[T]):
    timestamp: datetime
    value: T


class KeyedSlidingWindow(Generic[K, T]):
    """An event-time window with LRU key, per-key, and global capacity bounds.

    A small amount of out-of-order input is accepted. Records older than one full
    window behind the high-water mark are ignored, preventing stale sensor files from
    reintroducing old state after rotation. LRU eviction makes adversarial cardinality
    and single-key floods finite rather than allowing detector memory to grow forever.
    """

    def __init__(
        self,
        *,
        window_seconds: float,
        max_keys: int,
        max_values_per_key: int = 2_048,
        max_total_values: int = 250_000,
    ) -> None:
        if min(window_seconds, max_keys, max_values_per_key, max_total_values) <= 0:
            raise ValueError("window limits must be positive")
        if max_total_values < max_values_per_key:
            raise ValueError("max_total_values must be at least max_values_per_key")
        self._span = timedelta(seconds=window_seconds)
        self._max_keys = max_keys
        self._max_values_per_key = max_values_per_key
        self._max_total_values = max_total_values
        self._windows: OrderedDict[K, deque[TimedValue[T]]] = OrderedDict()
        self._watermark: datetime | None = None
        self._value_count = 0
        self.evicted_keys = 0
        self.evicted_values = 0
        self.late_events = 0

    def add(self, key: K, timestamp: datetime, value: T) -> tuple[TimedValue[T], ...]:
        if self._watermark is None or timestamp > self._watermark:
            self._watermark = timestamp
        assert self._watermark is not None
        oldest_accepted = self._watermark - self._span
        if timestamp < oldest_accepted:
            self.late_events += 1
            return self.values(key, reference=self._watermark)

        window = self._windows.get(key)
        if window is None:
            window = deque()
            self._windows[key] = window
        else:
            self._windows.move_to_end(key)
        previous_length = len(window)

        item = TimedValue(timestamp=timestamp, value=value)
        if not window or timestamp >= window[-1].timestamp:
            window.append(item)
        else:
            values = list(window)
            position = bisect_right([entry.timestamp for entry in values], timestamp)
            values.insert(position, item)
            window = deque(values)
            self._windows[key] = window

        self._prune(window, self._watermark - self._span)
        self._value_count += len(window) - previous_length
        while len(window) > self._max_values_per_key:
            window.popleft()
            self._value_count -= 1
            self.evicted_values += 1
        while len(self._windows) > self._max_keys or self._value_count > self._max_total_values:
            _, evicted = self._windows.popitem(last=False)
            self._value_count -= len(evicted)
            self.evicted_values += len(evicted)
            self.evicted_keys += 1
        return tuple(self._windows.get(key, ()))

    def values(self, key: K, *, reference: datetime | None = None) -> tuple[TimedValue[T], ...]:
        window = self._windows.get(key)
        if window is None:
            return ()
        if reference is not None:
            previous_length = len(window)
            self._prune(window, reference - self._span)
            self._value_count -= previous_length - len(window)
            if not window:
                del self._windows[key]
                return ()
        return tuple(window)

    @property
    def key_count(self) -> int:
        return len(self._windows)

    @property
    def value_count(self) -> int:
        return self._value_count

    @staticmethod
    def _prune(window: deque[TimedValue[T]], cutoff: datetime) -> None:
        while window and window[0].timestamp < cutoff:
            window.popleft()
