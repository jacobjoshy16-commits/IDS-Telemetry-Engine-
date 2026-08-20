from __future__ import annotations

from pathlib import Path

import pytest

from ids_telemetry.models import BaseTelemetryEvent, MetricSnapshot, SensorIdentity
from ids_telemetry.parsers import parse_suricata_line
from ids_telemetry.sinks.base import CompositeSink, NullSink
from ids_telemetry.sinks.router import OutputRouter


class RecordingSink:
    def __init__(self) -> None:
        self.documents: list[BaseTelemetryEvent] = []
        self.closed = 0

    async def emit(self, document: BaseTelemetryEvent) -> None:
        self.documents.append(document)

    async def close(self) -> None:
        self.closed += 1


@pytest.mark.asyncio
async def test_composite_and_null_sinks(fixture_dir: Path) -> None:
    event = parse_suricata_line(
        (fixture_dir / "suricata_eve.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    first = RecordingSink()
    second = RecordingSink()
    composite = CompositeSink((first, second, NullSink()))
    await composite.emit(event)
    await composite.close()
    assert first.documents == [event]
    assert second.documents == [event]
    assert first.closed == second.closed == 1


@pytest.mark.asyncio
async def test_router_sends_document_types_to_expected_outputs(fixture_dir: Path) -> None:
    event = parse_suricata_line(
        (fixture_dir / "suricata_eve.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    local = RecordingSink()
    remote = RecordingSink()
    router = OutputRouter(
        json_sink=local,
        opensearch_sink=remote,
        include_normalized_events=False,
        include_metric_snapshots=False,
    )
    await router.emit_event(event)
    snapshot = MetricSnapshot(
        event_id="metric-00000001",
        observed_at=event.observed_at,
        sensor=SensorIdentity(product="ids-telemetry-engine", sensor_id="test"),
        interval_seconds=60.0,
        counters={},
        gauges={},
    )
    await router.emit_metric(snapshot)
    await router.close()

    assert local.documents == []
    assert remote.documents == [event, snapshot]
    assert local.closed == remote.closed == 1
