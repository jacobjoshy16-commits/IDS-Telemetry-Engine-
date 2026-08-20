from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ids_telemetry.config import OpenSearchSettings
from ids_telemetry.opensearch.client import OpenSearchAuthEventLookup
from ids_telemetry.parsers import parse_suricata_line
from ids_telemetry.sinks.opensearch import OpenSearchBulkSink


class FakeSearchClient:
    def __init__(self, source: dict[str, Any]) -> None:
        self.source = source
        self.index: str | None = None
        self.body: dict[str, Any] | None = None

    def search(self, *, index: str, body: dict[str, Any], **_: object) -> dict[str, Any]:
        self.index = index
        self.body = body
        return {"hits": {"hits": [{"_id": "remote-auth-01", "_source": self.source}]}}


@pytest.mark.asyncio
async def test_auth_lookup_uses_time_and_endpoint_filters() -> None:
    source = {
        "@timestamp": "2026-01-15T12:00:00Z",
        "event": {"action": "logon-failed", "outcome": "failure", "provider": "auditd"},
        "host": {"name": "workstation", "ip": ["10.0.0.25"]},
        "source": {"ip": "198.51.100.42"},
        "user": {"name": "alice"},
    }
    client = FakeSearchClient(source)
    settings = OpenSearchSettings(auth_index_pattern="auth-*")
    lookup = OpenSearchAuthEventLookup(client, settings)  # type: ignore[arg-type]
    start = datetime(2026, 1, 15, 11, 55, tzinfo=UTC)
    end = datetime(2026, 1, 15, 12, 5, tzinfo=UTC)

    events = await lookup.search(
        endpoints=(__import__("ipaddress").ip_address("10.0.0.25"),),
        start=start,
        end=end,
        limit=5,
    )

    assert events[0].event_id == "remote-auth-01"
    assert client.index == "auth-*"
    assert client.body is not None
    assert client.body["query"]["bool"]["minimum_should_match"] == 1
    assert (
        client.body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == start.isoformat()
    )


class FakeBulkClient:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[list[dict[str, Any]]] = []
        self.fail = fail

    def bulk(self, *, body: list[dict[str, Any]], **_: object) -> dict[str, Any]:
        self.calls.append(body)
        if self.fail:
            raise RuntimeError("unavailable")
        return {"errors": False, "items": []}


@pytest.mark.asyncio
async def test_bulk_sink_uses_daily_idempotent_index(fixture_dir: Path) -> None:
    event = parse_suricata_line(
        (fixture_dir / "suricata_eve.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    client = FakeBulkClient()
    settings = OpenSearchSettings(batch_size=1, flush_interval_seconds=0.01)
    sink = OpenSearchBulkSink(client, settings, queue_size=10)  # type: ignore[arg-type]

    await sink.emit(event)
    await sink.close()

    assert sink.indexed_documents == 1
    action = client.calls[0][0]["index"]
    assert action["_index"] == "ids-telemetry-events-2026.01.15"
    assert action["_id"] == event.event_id
    assert client.calls[0][1]["kind"] == "suricata.alert"


@pytest.mark.asyncio
async def test_bulk_sink_counts_documents_after_retry_exhaustion(
    fixture_dir: Path, tmp_path: Path
) -> None:
    event = parse_suricata_line(
        (fixture_dir / "suricata_eve.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    client = FakeBulkClient(fail=True)
    dead_letter = tmp_path / "failed.jsonl"
    settings = OpenSearchSettings(
        batch_size=1,
        max_retries=0,
        dead_letter_path=dead_letter,
    )
    sink = OpenSearchBulkSink(client, settings, queue_size=10)  # type: ignore[arg-type]
    await sink.emit(event)
    await sink.close()
    assert sink.failed_documents == 1
    failed = __import__("json").loads(dead_letter.read_text(encoding="utf-8"))
    assert failed["target_index"] == "ids-telemetry-events-2026.01.15"
    assert failed["document"]["event_id"] == event.event_id
