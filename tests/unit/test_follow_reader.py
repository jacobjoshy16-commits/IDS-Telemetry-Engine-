from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ids_telemetry.ingest.readers import SourceDefinition, follow_source
from ids_telemetry.metrics import EngineMetrics
from ids_telemetry.models import SuricataAlert
from ids_telemetry.parsers import parse_suricata_line


@pytest.mark.asyncio
async def test_follower_reads_existing_file_then_detects_replacement(
    fixture_dir: Path, tmp_path: Path
) -> None:
    lines = (fixture_dir / "suricata_eve.jsonl").read_text(encoding="utf-8").splitlines()
    source_path = tmp_path / "eve.json"
    source_path.write_text(lines[0] + "\n", encoding="utf-8")
    queue: asyncio.Queue[object] = asyncio.Queue()
    task = asyncio.create_task(
        follow_source(
            SourceDefinition("suricata", source_path, parse_suricata_line),
            queue,
            from_beginning=True,
            poll_interval_seconds=0.01,
            metrics=EngineMetrics(service_name="follow-test"),
        )
    )
    try:
        first = await asyncio.wait_for(queue.get(), timeout=1)
        replacement = tmp_path / "replacement.json"
        replacement.write_text(lines[1] + "\n", encoding="utf-8")
        replacement.replace(source_path)
        second = await asyncio.wait_for(queue.get(), timeout=1)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    assert isinstance(first, SuricataAlert)
    assert isinstance(second, SuricataAlert)
    assert first.signature_id != second.signature_id


@pytest.mark.asyncio
async def test_follower_waits_for_file_creation(fixture_dir: Path, tmp_path: Path) -> None:
    line = (fixture_dir / "suricata_eve.jsonl").read_text(encoding="utf-8").splitlines()[0]
    source_path = tmp_path / "later.json"
    queue: asyncio.Queue[object] = asyncio.Queue()
    task = asyncio.create_task(
        follow_source(
            SourceDefinition("suricata", source_path, parse_suricata_line),
            queue,
            from_beginning=True,
            poll_interval_seconds=0.01,
            metrics=EngineMetrics(service_name="follow-test"),
        )
    )
    try:
        await asyncio.sleep(0.03)
        source_path.write_text(line + "\n", encoding="utf-8")
        event = await asyncio.wait_for(queue.get(), timeout=1)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert isinstance(event, SuricataAlert)
