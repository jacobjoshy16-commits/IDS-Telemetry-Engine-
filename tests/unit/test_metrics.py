from __future__ import annotations

from pathlib import Path

from ids_telemetry.metrics import EngineMetrics
from ids_telemetry.parsers import parse_suricata_line


def test_metrics_expose_prometheus_and_structured_snapshot(fixture_dir: Path) -> None:
    event = parse_suricata_line(
        (fixture_dir / "suricata_eve.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    metrics = EngineMetrics(service_name="test-engine")
    metrics.record_event(event)
    metrics.record_parse_error("zeek")
    metrics.set_queue_depth(7)
    metrics.observe_processing(0.001)

    snapshot = metrics.snapshot(sensor_id="test-01", interval_seconds=60.0)

    assert snapshot.counters["events.total"] == 1
    assert snapshot.counters["events.suricata.alert"] == 1
    assert snapshot.counters["parse_errors.total"] == 1
    assert snapshot.gauges["queue.depth"] == 7.0
    assert snapshot.event_id.startswith("metric-")
