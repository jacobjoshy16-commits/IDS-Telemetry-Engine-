from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from ids_telemetry.models import AuthOutcome, SuricataAlert
from ids_telemetry.normalization import ParseError
from ids_telemetry.parsers import (
    parse_endpoint_auth_line,
    parse_suricata_line,
    parse_zeek_conn_line,
    parse_zeek_dns_line,
)


def first_line(path: Path) -> str:
    return path.read_text(encoding="utf-8").splitlines()[0]


def test_suricata_eve_is_normalized(fixture_dir: Path) -> None:
    alert = parse_suricata_line(first_line(fixture_dir / "suricata_eve.jsonl"))

    assert str(alert.src_ip) == "10.0.0.25"
    assert alert.dst_port == 443
    assert alert.transport == "tcp"
    assert alert.signature_id == 2027757
    assert alert.metadata["mitre_tactic_id"] == ("TA0011",)
    assert alert.observed_at.isoformat() == "2026-01-15T12:01:40+00:00"
    assert alert.event_id.startswith("suri-")


def test_suricata_ids_are_stable(fixture_dir: Path) -> None:
    line = first_line(fixture_dir / "suricata_eve.jsonl")
    assert parse_suricata_line(line).event_id == parse_suricata_line(line).event_id


def test_suricata_rejects_non_alert_event() -> None:
    with pytest.raises(ParseError, match="event_type"):
        parse_suricata_line('{"event_type":"flow"}')


def test_zeek_connection_is_normalized(fixture_dir: Path) -> None:
    event = parse_zeek_conn_line(first_line(fixture_dir / "zeek_conn.jsonl"))

    assert event.uid == "Cbeacon00"
    assert event.conn_state == "SF"
    assert event.orig_bytes == 128
    assert event.resp_packets == 4
    assert event.service == "ssl"


def test_zeek_dns_is_normalized(fixture_dir: Path) -> None:
    event = parse_zeek_dns_line(first_line(fixture_dir / "zeek_dns.jsonl"))

    assert event.qtype == "TXT"
    assert event.rcode == "NXDOMAIN"
    assert event.query.endswith(".exfil.example")
    assert event.answers == ()
    assert event.rejected is False


def test_zeek_parser_checks_log_stream(fixture_dir: Path) -> None:
    raw = json.loads(first_line(fixture_dir / "zeek_conn.jsonl"))
    raw["_path"] = "dns"
    with pytest.raises(ParseError, match="_path"):
        parse_zeek_conn_line(json.dumps(raw))


def test_endpoint_ecs_shapes_are_normalized(fixture_dir: Path) -> None:
    event = parse_endpoint_auth_line(first_line(fixture_dir / "endpoint_auth.jsonl"))

    assert event.event_id == "auth-event-0001"
    assert event.outcome is AuthOutcome.FAILURE
    assert str(event.host_ip) == "10.0.0.25"
    assert event.principal == "ACME\\alice"
    assert event.provider == "Microsoft-Windows-Security-Auditing"


def test_malformed_json_is_a_parse_error() -> None:
    with pytest.raises(ParseError, match="invalid json"):
        parse_zeek_dns_line("{nope")


def test_canonical_models_are_strict_and_forbid_extra_fields(fixture_dir: Path) -> None:
    alert = parse_suricata_line(first_line(fixture_dir / "suricata_eve.jsonl"))
    document = alert.model_dump()
    document["severity"] = "1"
    document["undocumented"] = True

    with pytest.raises(ValidationError) as exc_info:
        SuricataAlert.model_validate(document)
    errors = exc_info.value.errors()
    assert {error["type"] for error in errors} >= {"int_type", "extra_forbidden"}
