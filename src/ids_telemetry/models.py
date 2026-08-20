"""Canonical, strict telemetry and detection schemas.

Raw sensor documents never move beyond the parser boundary.  Every event entering the
correlation engine is represented by one of the frozen models in this module.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

IpAddress = IPv4Address | IPv6Address
Port = Annotated[int, Field(strict=True, ge=0, le=65535)]
NonNegativeInt = Annotated[int, Field(strict=True, ge=0)]
PositiveInt = Annotated[int, Field(strict=True, gt=0)]
UnitFloat = Annotated[float, Field(strict=True, ge=0.0, le=1.0)]


class EventKind(StrEnum):
    """Discriminator values used by canonical telemetry documents."""

    SURICATA_ALERT = "suricata.alert"
    ZEEK_CONN = "zeek.conn"
    ZEEK_DNS = "zeek.dns"
    ENDPOINT_AUTH = "endpoint.auth"
    CORRELATION_ALERT = "correlation.alert"
    METRIC_SNAPSHOT = "engine.metric"


class AuthOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class DetectionType(StrEnum):
    BEACONING = "c2_beaconing"
    DNS_TUNNELING = "dns_tunneling"


class AlertSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StrictModel(BaseModel):
    """Shared model policy: no coercion, mutation, or undocumented fields."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        allow_inf_nan=False,
        validate_default=True,
    )


class SensorIdentity(StrictModel):
    product: Literal["suricata", "zeek", "endpoint", "ids-telemetry-engine"]
    sensor_id: Annotated[str, Field(min_length=1, max_length=128)]
    interface: Annotated[str | None, Field(max_length=128)] = None


class BaseTelemetryEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    event_id: Annotated[str, Field(min_length=8, max_length=128)]
    kind: EventKind
    observed_at: datetime
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    sensor: SensorIdentity

    @field_validator("observed_at", "ingested_at")
    @classmethod
    def require_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include a UTC offset")
        return value.astimezone(UTC)


class NetworkTelemetryEvent(BaseTelemetryEvent):
    src_ip: IpAddress
    src_port: Port | None = None
    dst_ip: IpAddress
    dst_port: Port | None = None
    transport: Annotated[str, Field(min_length=1, max_length=16)]
    community_id: Annotated[str | None, Field(max_length=128)] = None


class SuricataAlert(NetworkTelemetryEvent):
    kind: Literal[EventKind.SURICATA_ALERT] = EventKind.SURICATA_ALERT
    flow_id: Annotated[str | None, Field(max_length=64)] = None
    app_protocol: Annotated[str | None, Field(max_length=64)] = None
    action: Annotated[str, Field(min_length=1, max_length=64)]
    signature_id: NonNegativeInt
    signature_revision: NonNegativeInt | None = None
    signature: Annotated[str, Field(min_length=1, max_length=1024)]
    category: Annotated[str, Field(min_length=1, max_length=256)]
    # Suricata's severity is conventionally 1 (highest) through 4 (lowest).
    severity: Annotated[int, Field(strict=True, ge=1, le=255)]
    metadata: dict[str, tuple[str, ...]] = Field(default_factory=dict)


class ZeekConnection(NetworkTelemetryEvent):
    kind: Literal[EventKind.ZEEK_CONN] = EventKind.ZEEK_CONN
    uid: Annotated[str, Field(min_length=1, max_length=128)]
    service: Annotated[str | None, Field(max_length=64)] = None
    duration_seconds: Annotated[float | None, Field(strict=True, ge=0.0)] = None
    orig_bytes: NonNegativeInt | None = None
    resp_bytes: NonNegativeInt | None = None
    orig_packets: NonNegativeInt | None = None
    resp_packets: NonNegativeInt | None = None
    conn_state: Annotated[str, Field(min_length=1, max_length=16)]
    history: Annotated[str | None, Field(max_length=256)] = None
    missed_bytes: NonNegativeInt = 0


class ZeekDnsQuery(NetworkTelemetryEvent):
    kind: Literal[EventKind.ZEEK_DNS] = EventKind.ZEEK_DNS
    uid: Annotated[str, Field(min_length=1, max_length=128)]
    query: Annotated[str, Field(min_length=1, max_length=253)]
    qtype: Annotated[str, Field(min_length=1, max_length=32)]
    rcode: Annotated[str | None, Field(max_length=32)] = None
    answers: tuple[str, ...] = ()
    rejected: bool = False
    trans_id: NonNegativeInt | None = None


class EndpointAuthEvent(BaseTelemetryEvent):
    kind: Literal[EventKind.ENDPOINT_AUTH] = EventKind.ENDPOINT_AUTH
    host_name: Annotated[str, Field(min_length=1, max_length=255)]
    host_ip: IpAddress | None = None
    source_ip: IpAddress | None = None
    principal: Annotated[str, Field(min_length=1, max_length=512)]
    outcome: AuthOutcome
    action: Annotated[str, Field(min_length=1, max_length=128)]
    provider: Annotated[str, Field(min_length=1, max_length=128)]
    logon_type: Annotated[str | None, Field(max_length=128)] = None


TelemetryEvent = Annotated[
    SuricataAlert | ZeekConnection | ZeekDnsQuery | EndpointAuthEvent,
    Field(discriminator="kind"),
]


class AttackTechnique(StrictModel):
    technique_id: Annotated[str, Field(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")]
    name: Annotated[str, Field(min_length=1, max_length=256)]
    tactic: Annotated[str, Field(min_length=1, max_length=128)]
    url: Annotated[str, Field(min_length=1, max_length=512)]


class NistControl(StrictModel):
    control_id: Annotated[str, Field(pattern=r"^[A-Z]{2}-[0-9]+(?:\([0-9]+\))?$")]
    name: Annotated[str, Field(min_length=1, max_length=256)]
    rationale: Annotated[str, Field(min_length=1, max_length=1024)]


class SuricataEvidence(StrictModel):
    event_id: Annotated[str, Field(min_length=8, max_length=128)]
    signature_id: NonNegativeInt
    signature: Annotated[str, Field(min_length=1, max_length=1024)]
    category: Annotated[str, Field(min_length=1, max_length=256)]
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def require_timestamp_zone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include a UTC offset")
        return value.astimezone(UTC)


class AuthEvidence(StrictModel):
    event_id: Annotated[str, Field(min_length=8, max_length=128)]
    observed_at: datetime
    host_name: Annotated[str, Field(min_length=1, max_length=255)]
    principal: Annotated[str, Field(min_length=1, max_length=512)]
    outcome: AuthOutcome
    action: Annotated[str, Field(min_length=1, max_length=128)]
    provider: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("observed_at")
    @classmethod
    def require_timestamp_zone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include a UTC offset")
        return value.astimezone(UTC)


class CorrelationAlert(BaseTelemetryEvent):
    kind: Literal[EventKind.CORRELATION_ALERT] = EventKind.CORRELATION_ALERT
    detection_type: DetectionType
    title: Annotated[str, Field(min_length=1, max_length=256)]
    description: Annotated[str, Field(min_length=1, max_length=2048)]
    severity: AlertSeverity
    confidence: UnitFloat
    first_seen: datetime
    last_seen: datetime
    src_ip: IpAddress
    dst_ip: IpAddress | None = None
    dst_port: Port | None = None
    transport: Annotated[str | None, Field(max_length=16)] = None
    event_ids: tuple[str, ...]
    evidence: dict[str, JsonValue]
    suricata_matches: tuple[SuricataEvidence, ...] = ()
    authentication_matches: tuple[AuthEvidence, ...] = ()
    mitre_attack: tuple[AttackTechnique, ...]
    nist_controls: tuple[NistControl, ...]
    tags: tuple[str, ...] = ()

    @field_validator("first_seen", "last_seen")
    @classmethod
    def require_window_timestamp_zone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include a UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_ordered_window(self) -> Self:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        return self


class MetricSnapshot(BaseTelemetryEvent):
    kind: Literal[EventKind.METRIC_SNAPSHOT] = EventKind.METRIC_SNAPSHOT
    interval_seconds: Annotated[float, Field(strict=True, gt=0.0)]
    counters: dict[str, NonNegativeInt]
    gauges: dict[str, float]


SI4_CONTROL = NistControl(
    control_id="SI-4",
    name="System Monitoring",
    rationale="Continuously monitors network communications and analyzes detected events.",
)
SC7_CONTROL = NistControl(
    control_id="SC-7",
    name="Boundary Protection",
    rationale="Observes and correlates traffic crossing managed network boundaries.",
)
NETWORK_MONITORING_CONTROLS: tuple[NistControl, ...] = (SC7_CONTROL, SI4_CONTROL)

BEACON_TECHNIQUES: tuple[AttackTechnique, ...] = (
    AttackTechnique(
        technique_id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
        url="https://attack.mitre.org/techniques/T1071/",
    ),
)
DNS_TUNNEL_TECHNIQUES: tuple[AttackTechnique, ...] = (
    AttackTechnique(
        technique_id="T1071.004",
        name="Application Layer Protocol: DNS",
        tactic="Command and Control",
        url="https://attack.mitre.org/techniques/T1071/004/",
    ),
    AttackTechnique(
        technique_id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic="Exfiltration",
        url="https://attack.mitre.org/techniques/T1048/",
    ),
)
