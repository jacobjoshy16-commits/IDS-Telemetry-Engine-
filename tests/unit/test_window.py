from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ids_telemetry.correlation.window import KeyedSlidingWindow


def test_window_sorts_out_of_order_and_expires_old_values() -> None:
    base = datetime(2026, 1, 1, tzinfo=UTC)
    window: KeyedSlidingWindow[str, str] = KeyedSlidingWindow(window_seconds=60, max_keys=10)

    window.add("key", base + timedelta(seconds=20), "third")
    window.add("key", base, "first")
    entries = window.add("key", base + timedelta(seconds=10), "second")
    assert [entry.value for entry in entries] == ["first", "second", "third"]

    entries = window.add("key", base + timedelta(seconds=70), "new")
    assert [entry.value for entry in entries] == ["second", "third", "new"]


def test_window_rejects_events_older_than_watermark_window() -> None:
    base = datetime(2026, 1, 1, tzinfo=UTC)
    window: KeyedSlidingWindow[str, int] = KeyedSlidingWindow(window_seconds=10, max_keys=10)
    window.add("key", base + timedelta(seconds=20), 20)
    window.add("key", base, 0)
    assert window.late_events == 1
    assert [entry.value for entry in window.values("key")] == [20]


def test_window_lru_bounds_cardinality() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    window: KeyedSlidingWindow[str, int] = KeyedSlidingWindow(window_seconds=10, max_keys=2)
    window.add("a", now, 1)
    window.add("b", now, 2)
    window.add("c", now, 3)
    assert window.key_count == 2
    assert window.values("a") == ()
    assert window.evicted_keys == 1


def test_window_bounds_per_key_and_total_values() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    window: KeyedSlidingWindow[str, int] = KeyedSlidingWindow(
        window_seconds=60,
        max_keys=10,
        max_values_per_key=2,
        max_total_values=3,
    )
    window.add("a", now, 1)
    window.add("a", now + timedelta(seconds=1), 2)
    assert [entry.value for entry in window.add("a", now + timedelta(seconds=2), 3)] == [2, 3]
    window.add("b", now + timedelta(seconds=3), 4)
    window.add("b", now + timedelta(seconds=4), 5)
    assert window.values("a") == ()
    assert window.value_count == 2
    assert window.evicted_values == 3
