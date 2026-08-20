from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ids_telemetry.ingest.readers import SourceDefinition, replay_sources
from ids_telemetry.metrics import EngineMetrics
from ids_telemetry.parsers import parse_endpoint_auth_line, parse_zeek_conn_line


@pytest.mark.asyncio
async def test_replay_kway_merges_sources_by_event_time(fixture_dir: Path) -> None:
    queue: asyncio.Queue[object] = asyncio.Queue()
    metrics = EngineMetrics(service_name="reader-test")
    sources = (
        SourceDefinition("zeek.conn", fixture_dir / "zeek_conn.jsonl", parse_zeek_conn_line),
        SourceDefinition(
            "endpoint.auth", fixture_dir / "endpoint_auth.jsonl", parse_endpoint_auth_line
        ),
    )
    await replay_sources(sources, queue, metrics=metrics)
    events = []
    while not queue.empty():
        events.append(queue.get_nowait())
    timestamps = [event.observed_at for event in events]  # type: ignore[union-attr]
    assert timestamps == sorted(timestamps)
    assert events[0].kind.value == "endpoint.auth"  # type: ignore[union-attr]
