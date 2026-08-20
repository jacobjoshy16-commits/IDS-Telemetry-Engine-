"""Normalization for ECS-like endpoint authentication documents."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from ids_telemetry.models import AuthOutcome, EndpointAuthEvent, SensorIdentity
from ids_telemetry.normalization import (
    ParseError,
    load_json_object,
    nested_get,
    optional_text,
    parse_optional_ip,
    parse_timestamp,
    require_text,
    stable_event_id,
)

SENSOR = "endpoint"
_FAILURE_VALUES = {"failure", "failed", "denied", "invalid", "lockout"}
_SUCCESS_VALUES = {"success", "succeeded", "accepted", "allowed"}


def parse_endpoint_auth_line(
    line: str | bytes, *, sensor_id: str = "endpoint-01"
) -> EndpointAuthEvent:
    return parse_endpoint_auth(load_json_object(line, sensor=SENSOR), sensor_id=sensor_id)


def parse_endpoint_auth(
    document: dict[str, Any], *, sensor_id: str = "endpoint-01"
) -> EndpointAuthEvent:
    observed_at = parse_timestamp(
        nested_get(document, "@timestamp", "timestamp", "ts"),
        sensor=SENSOR,
        field="@timestamp",
    )
    host_name = require_text(
        nested_get(document, "host.name", "hostname", "computer_name"),
        sensor=SENSOR,
        field="host.name",
        maximum=255,
    )
    principal = require_text(
        nested_get(document, "user.name", "principal", "account_name"),
        sensor=SENSOR,
        field="user.name",
        maximum=512,
    )
    action = require_text(
        nested_get(document, "event.action", "action"),
        sensor=SENSOR,
        field="event.action",
        maximum=128,
    )
    provider = (
        optional_text(nested_get(document, "event.provider", "provider", "agent.type"), maximum=128)
        or "unknown"
    )
    outcome = _outcome(nested_get(document, "event.outcome", "outcome"))
    host_ip = parse_optional_ip(
        _first_ip(nested_get(document, "host.ip", "host_ip")),
        sensor=SENSOR,
        field="host.ip",
    )
    source_ip = parse_optional_ip(
        nested_get(document, "source.ip", "source_ip", "client.ip"),
        sensor=SENSOR,
        field="source.ip",
    )
    upstream_id = optional_text(nested_get(document, "event.id", "_id"), maximum=128)

    try:
        return EndpointAuthEvent(
            event_id=upstream_id
            or stable_event_id(
                "auth",
                sensor_id,
                observed_at.isoformat(),
                host_name,
                principal,
                action,
                source_ip,
            ),
            observed_at=observed_at,
            sensor=SensorIdentity(product="endpoint", sensor_id=sensor_id),
            host_name=host_name,
            host_ip=host_ip,
            source_ip=source_ip,
            principal=principal,
            outcome=outcome,
            action=action,
            provider=provider,
            logon_type=optional_text(
                nested_get(document, "winlog.logon.type", "logon.type", "logon_type"),
                maximum=128,
            ),
        )
    except ValidationError as exc:
        raise ParseError(SENSOR, "schema", str(exc)) from exc


def _outcome(value: Any) -> AuthOutcome:
    if value is None:
        return AuthOutcome.UNKNOWN
    lowered = str(value).strip().lower()
    if lowered in _FAILURE_VALUES:
        return AuthOutcome.FAILURE
    if lowered in _SUCCESS_VALUES:
        return AuthOutcome.SUCCESS
    return AuthOutcome.UNKNOWN


def _first_ip(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value
