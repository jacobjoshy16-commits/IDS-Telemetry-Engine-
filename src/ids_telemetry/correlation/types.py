"""Internal correlation candidate type shared by detectors and enrichment."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from ids_telemetry.models import AlertSeverity, AttackTechnique, DetectionType


@dataclass(frozen=True, slots=True)
class DetectionCandidate:
    detection_type: DetectionType
    title: str
    description: str
    severity: AlertSeverity
    confidence: float
    first_seen: datetime
    last_seen: datetime
    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address | None
    dst_port: int | None
    transport: str | None
    event_ids: tuple[str, ...]
    evidence: dict[str, Any]
    mitre_attack: tuple[AttackTechnique, ...]
    tags: tuple[str, ...]
    deduplication_key: str
