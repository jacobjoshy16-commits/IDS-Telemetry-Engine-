from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from ids_telemetry.config import BeaconSettings, DnsTunnelSettings
from ids_telemetry.correlation.beacon import BeaconDetector
from ids_telemetry.correlation.dns_tunnel import (
    DnsTunnelDetector,
    encoded_label,
    registrable_domain,
    shannon_entropy,
)
from ids_telemetry.models import DetectionType
from ids_telemetry.parsers import parse_zeek_conn_line, parse_zeek_dns_line


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def test_beacon_detector_finds_bounded_jitter(fixture_dir: Path) -> None:
    detector = BeaconDetector(BeaconSettings())
    candidates = [
        candidate
        for line in _lines(fixture_dir / "zeek_conn.jsonl")
        if (candidate := detector.observe(parse_zeek_conn_line(line))) is not None
    ]

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.detection_type is DetectionType.BEACONING
    assert candidate.evidence["connection_count"] == 8
    assert 28 <= candidate.evidence["median_interval_seconds"] <= 32
    assert candidate.confidence >= 0.8
    assert candidate.mitre_attack[0].technique_id == "T1071"


def test_beacon_detector_rejects_irregular_connections(fixture_dir: Path) -> None:
    template = parse_zeek_conn_line(_lines(fixture_dir / "zeek_conn.jsonl")[0])
    detector = BeaconDetector(BeaconSettings())
    intervals = (0, 5, 150, 157, 450, 500, 810, 900)
    results = []
    for index, seconds in enumerate(intervals):
        event = template.model_copy(
            update={
                "event_id": f"irregular-{index:03d}",
                "observed_at": template.observed_at + timedelta(seconds=seconds),
            }
        )
        results.append(detector.observe(event))
    assert all(result is None for result in results)


def test_dns_tunnel_detector_combines_shape_entropy_and_rate(fixture_dir: Path) -> None:
    detector = DnsTunnelDetector(DnsTunnelSettings())
    candidates = [
        candidate
        for line in _lines(fixture_dir / "zeek_dns.jsonl")
        if (candidate := detector.observe(parse_zeek_dns_line(line))) is not None
    ]

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.detection_type is DetectionType.DNS_TUNNELING
    assert candidate.evidence["root_domain"] == "exfil.example"
    assert candidate.evidence["high_entropy_ratio"] == 1.0
    assert {mapping.technique_id for mapping in candidate.mitre_attack} == {
        "T1071.004",
        "T1048",
    }


def test_dns_allowlist_suppresses_candidate(fixture_dir: Path) -> None:
    settings = DnsTunnelSettings(allowlisted_domains=("example",))
    detector = DnsTunnelDetector(settings)
    assert all(
        detector.observe(parse_zeek_dns_line(line)) is None
        for line in _lines(fixture_dir / "zeek_dns.jsonl")
    )


def test_dns_feature_helpers_cover_multilabel_suffixes() -> None:
    query = "encoded.payload.service.co.uk"
    assert registrable_domain(query) == "service.co.uk"
    assert encoded_label(query, "service.co.uk") == "encoded"
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("abcdefgh") == 3.0
