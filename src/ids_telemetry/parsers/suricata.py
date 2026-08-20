"""Suricata EVE JSON alert normalization."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from ids_telemetry.models import SensorIdentity, SuricataAlert
from ids_telemetry.normalization import (
    ParseError,
    load_json_object,
    optional_text,
    parse_int,
    parse_ip,
    parse_optional_int,
    parse_timestamp,
    require_text,
    stable_event_id,
)

SENSOR = "suricata"


def parse_suricata_line(line: str | bytes, *, sensor_id: str = "suricata-01") -> SuricataAlert:
    return parse_suricata_alert(load_json_object(line, sensor=SENSOR), sensor_id=sensor_id)


def parse_suricata_alert(
    document: dict[str, Any], *, sensor_id: str = "suricata-01"
) -> SuricataAlert:
    if document.get("event_type") != "alert":
        raise ParseError(SENSOR, "event_type", "expected 'alert'")
    alert = document.get("alert")
    if not isinstance(alert, dict):
        raise ParseError(SENSOR, "alert", "expected object")

    observed_at = parse_timestamp(document.get("timestamp"), sensor=SENSOR)
    src_ip = parse_ip(document.get("src_ip"), sensor=SENSOR, field="src_ip")
    dst_ip = parse_ip(document.get("dest_ip"), sensor=SENSOR, field="dest_ip")
    signature_id = parse_int(
        alert.get("signature_id"), sensor=SENSOR, field="alert.signature_id", minimum=0
    )
    flow_id = optional_text(document.get("flow_id"), maximum=64)
    transport = require_text(
        document.get("proto"), sensor=SENSOR, field="proto", maximum=16
    ).lower()
    metadata = _parse_metadata(alert.get("metadata"))

    event_id = stable_event_id(
        "suri",
        sensor_id,
        observed_at.isoformat(),
        flow_id,
        signature_id,
        src_ip,
        document.get("src_port"),
        dst_ip,
        document.get("dest_port"),
    )
    try:
        return SuricataAlert(
            event_id=event_id,
            observed_at=observed_at,
            sensor=SensorIdentity(
                product="suricata",
                sensor_id=sensor_id,
                interface=optional_text(document.get("in_iface"), maximum=128),
            ),
            src_ip=src_ip,
            src_port=parse_optional_int(
                document.get("src_port"),
                sensor=SENSOR,
                field="src_port",
                minimum=0,
                maximum=65535,
            ),
            dst_ip=dst_ip,
            dst_port=parse_optional_int(
                document.get("dest_port"),
                sensor=SENSOR,
                field="dest_port",
                minimum=0,
                maximum=65535,
            ),
            transport=transport,
            community_id=optional_text(document.get("community_id"), maximum=128),
            flow_id=flow_id,
            app_protocol=optional_text(document.get("app_proto"), maximum=64),
            action=optional_text(alert.get("action"), maximum=64) or "unknown",
            signature_id=signature_id,
            signature_revision=parse_optional_int(
                alert.get("rev"), sensor=SENSOR, field="alert.rev", minimum=0
            ),
            signature=require_text(
                alert.get("signature"),
                sensor=SENSOR,
                field="alert.signature",
                maximum=1024,
            ),
            category=require_text(
                alert.get("category", "Unknown Traffic"),
                sensor=SENSOR,
                field="alert.category",
                maximum=256,
            ),
            severity=parse_int(
                alert.get("severity", 3),
                sensor=SENSOR,
                field="alert.severity",
                minimum=1,
                maximum=255,
            ),
            metadata=metadata,
        )
    except ValidationError as exc:
        raise ParseError(SENSOR, "schema", str(exc)) from exc


def _parse_metadata(value: Any) -> dict[str, tuple[str, ...]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ParseError(SENSOR, "alert.metadata", "expected object")
    parsed: dict[str, tuple[str, ...]] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key)[:128]
        if isinstance(raw_value, list):
            parsed[key] = tuple(str(item)[:512] for item in raw_value)
        elif raw_value is None:
            parsed[key] = ()
        else:
            parsed[key] = (str(raw_value)[:512],)
    return parsed
