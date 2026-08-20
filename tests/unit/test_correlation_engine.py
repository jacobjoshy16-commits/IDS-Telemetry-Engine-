from __future__ import annotations

from pathlib import Path

import pytest

from ids_telemetry.config import CorrelationSettings
from ids_telemetry.correlation.engine import CorrelationEngine
from ids_telemetry.models import (
    AlertSeverity,
    AuthOutcome,
    DetectionType,
    EndpointAuthEvent,
    TelemetryEvent,
)
from ids_telemetry.parsers import (
    parse_endpoint_auth_line,
    parse_suricata_line,
    parse_zeek_conn_line,
    parse_zeek_dns_line,
)


def _parse_fixture(path: Path, parser: object) -> list[TelemetryEvent]:
    return [parser(line) for line in path.read_text(encoding="utf-8").splitlines()]  # type: ignore[operator]


@pytest.mark.asyncio
async def test_engine_enriches_network_detection_with_auth_and_suricata(
    fixture_dir: Path,
) -> None:
    events = [
        *_parse_fixture(fixture_dir / "suricata_eve.jsonl", parse_suricata_line),
        *_parse_fixture(fixture_dir / "zeek_conn.jsonl", parse_zeek_conn_line),
        *_parse_fixture(fixture_dir / "endpoint_auth.jsonl", parse_endpoint_auth_line),
    ]
    events.sort(key=lambda event: event.observed_at)
    engine = CorrelationEngine(CorrelationSettings())
    alerts = []
    for event in events:
        alerts.extend(await engine.process(event))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detection_type is DetectionType.BEACONING
    assert alert.severity is AlertSeverity.CRITICAL
    assert alert.confidence == 1.0
    assert len(alert.authentication_matches) == 2
    assert all(match.outcome is AuthOutcome.FAILURE for match in alert.authentication_matches)
    assert alert.suricata_matches[0].signature_id == 2027757
    assert {control.control_id for control in alert.nist_controls} == {"SC-7", "SI-4"}
    assert alert.event_id.startswith("corr-")


class FakeAuthLookup:
    def __init__(self, event: EndpointAuthEvent | None = None, *, fail: bool = False) -> None:
        self.event = event
        self.fail = fail
        self.calls = 0

    async def search(self, **_: object) -> tuple[EndpointAuthEvent, ...]:
        self.calls += 1
        if self.fail:
            raise RuntimeError("OpenSearch unavailable")
        return (self.event,) if self.event is not None else ()


@pytest.mark.asyncio
async def test_remote_auth_lookup_runs_only_after_candidate(fixture_dir: Path) -> None:
    auth = parse_endpoint_auth_line(
        (fixture_dir / "endpoint_auth.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    lookup = FakeAuthLookup(auth)
    engine = CorrelationEngine(CorrelationSettings(), auth_lookup=lookup)
    connection_lines = (fixture_dir / "zeek_conn.jsonl").read_text(encoding="utf-8").splitlines()

    for line in connection_lines[:7]:
        assert await engine.process(parse_zeek_conn_line(line)) == ()
    assert lookup.calls == 0

    alerts = await engine.process(parse_zeek_conn_line(connection_lines[7]))
    assert lookup.calls == 1
    assert alerts[0].authentication_matches[0].event_id == auth.event_id


@pytest.mark.asyncio
async def test_detection_survives_auth_lookup_outage(fixture_dir: Path) -> None:
    lookup = FakeAuthLookup(fail=True)
    engine = CorrelationEngine(CorrelationSettings(), auth_lookup=lookup)
    lines = (fixture_dir / "zeek_dns.jsonl").read_text(encoding="utf-8").splitlines()
    alerts = []
    for line in lines:
        alerts.extend(await engine.process(parse_zeek_dns_line(line)))

    assert len(alerts) == 1
    assert alerts[0].detection_type is DetectionType.DNS_TUNNELING
    assert engine.auth_lookup_errors == 1
    assert alerts[0].authentication_matches == ()
