"""Zeek JSON conn.log and dns.log normalization."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from ids_telemetry.models import SensorIdentity, ZeekConnection, ZeekDnsQuery
from ids_telemetry.normalization import (
    ParseError,
    load_json_object,
    optional_text,
    parse_bool,
    parse_int,
    parse_ip,
    parse_optional_float,
    parse_optional_int,
    parse_timestamp,
    require_text,
    stable_event_id,
)

SENSOR = "zeek"


def parse_zeek_conn_line(line: str | bytes, *, sensor_id: str = "zeek-01") -> ZeekConnection:
    return parse_zeek_conn(load_json_object(line, sensor=SENSOR), sensor_id=sensor_id)


def parse_zeek_dns_line(line: str | bytes, *, sensor_id: str = "zeek-01") -> ZeekDnsQuery:
    return parse_zeek_dns(load_json_object(line, sensor=SENSOR), sensor_id=sensor_id)


def parse_zeek_conn(document: dict[str, Any], *, sensor_id: str = "zeek-01") -> ZeekConnection:
    _verify_stream(document, "conn")
    observed_at = parse_timestamp(document.get("ts"), sensor=SENSOR, field="ts")
    uid = require_text(document.get("uid"), sensor=SENSOR, field="uid", maximum=128)
    src_ip = parse_ip(document.get("id.orig_h"), sensor=SENSOR, field="id.orig_h")
    dst_ip = parse_ip(document.get("id.resp_h"), sensor=SENSOR, field="id.resp_h")
    src_port = parse_optional_int(
        document.get("id.orig_p"),
        sensor=SENSOR,
        field="id.orig_p",
        minimum=0,
        maximum=65535,
    )
    dst_port = parse_optional_int(
        document.get("id.resp_p"),
        sensor=SENSOR,
        field="id.resp_p",
        minimum=0,
        maximum=65535,
    )
    transport = require_text(
        document.get("proto"), sensor=SENSOR, field="proto", maximum=16
    ).lower()

    try:
        return ZeekConnection(
            event_id=stable_event_id("zeek-conn", sensor_id, observed_at.isoformat(), uid),
            observed_at=observed_at,
            sensor=_sensor(document, sensor_id),
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            transport=transport,
            community_id=optional_text(document.get("community_id"), maximum=128),
            uid=uid,
            service=optional_text(document.get("service"), maximum=64),
            duration_seconds=parse_optional_float(
                document.get("duration"), sensor=SENSOR, field="duration", minimum=0.0
            ),
            orig_bytes=parse_optional_int(
                document.get("orig_bytes"), sensor=SENSOR, field="orig_bytes", minimum=0
            ),
            resp_bytes=parse_optional_int(
                document.get("resp_bytes"), sensor=SENSOR, field="resp_bytes", minimum=0
            ),
            orig_packets=parse_optional_int(
                document.get("orig_pkts"), sensor=SENSOR, field="orig_pkts", minimum=0
            ),
            resp_packets=parse_optional_int(
                document.get("resp_pkts"), sensor=SENSOR, field="resp_pkts", minimum=0
            ),
            conn_state=optional_text(document.get("conn_state"), maximum=16) or "OTH",
            history=optional_text(document.get("history"), maximum=256),
            missed_bytes=parse_optional_int(
                document.get("missed_bytes"), sensor=SENSOR, field="missed_bytes", minimum=0
            )
            or 0,
        )
    except ValidationError as exc:
        raise ParseError(SENSOR, "conn.schema", str(exc)) from exc


def parse_zeek_dns(document: dict[str, Any], *, sensor_id: str = "zeek-01") -> ZeekDnsQuery:
    _verify_stream(document, "dns")
    observed_at = parse_timestamp(document.get("ts"), sensor=SENSOR, field="ts")
    uid = require_text(document.get("uid"), sensor=SENSOR, field="uid", maximum=128)
    src_ip = parse_ip(document.get("id.orig_h"), sensor=SENSOR, field="id.orig_h")
    dst_ip = parse_ip(document.get("id.resp_h"), sensor=SENSOR, field="id.resp_h")
    query = require_text(document.get("query"), sensor=SENSOR, field="query", maximum=254)
    query = query.rstrip(".").lower()
    if not query:
        raise ParseError(SENSOR, "query", "root query is not analyzable")
    raw_answers = document.get("answers")
    if raw_answers in (None, "-"):
        answers: tuple[str, ...] = ()
    elif isinstance(raw_answers, list):
        answers = tuple(str(answer)[:512] for answer in raw_answers)
    else:
        raise ParseError(SENSOR, "answers", "expected array")

    qtype_value = optional_text(document.get("qtype_name"), maximum=32)
    if qtype_value is None and document.get("qtype") not in (None, "-"):
        qtype_value = f"TYPE{parse_int(document['qtype'], sensor=SENSOR, field='qtype', minimum=0)}"

    try:
        return ZeekDnsQuery(
            event_id=stable_event_id(
                "zeek-dns",
                sensor_id,
                observed_at.isoformat(),
                uid,
                document.get("trans_id"),
                query,
            ),
            observed_at=observed_at,
            sensor=_sensor(document, sensor_id),
            src_ip=src_ip,
            src_port=parse_optional_int(
                document.get("id.orig_p"),
                sensor=SENSOR,
                field="id.orig_p",
                minimum=0,
                maximum=65535,
            ),
            dst_ip=dst_ip,
            dst_port=parse_optional_int(
                document.get("id.resp_p"),
                sensor=SENSOR,
                field="id.resp_p",
                minimum=0,
                maximum=65535,
            ),
            transport=(optional_text(document.get("proto"), maximum=16) or "udp").lower(),
            community_id=optional_text(document.get("community_id"), maximum=128),
            uid=uid,
            query=query,
            qtype=(qtype_value or "UNKNOWN").upper(),
            rcode=(
                optional_text(document.get("rcode_name"), maximum=32)
                or optional_text(document.get("rcode"), maximum=32)
            ),
            answers=answers,
            rejected=parse_bool(
                document.get("rejected"), sensor=SENSOR, field="rejected", default=False
            ),
            trans_id=parse_optional_int(
                document.get("trans_id"), sensor=SENSOR, field="trans_id", minimum=0
            ),
        )
    except ValidationError as exc:
        raise ParseError(SENSOR, "dns.schema", str(exc)) from exc


def _verify_stream(document: dict[str, Any], expected: str) -> None:
    stream = document.get("_path") or document.get("path")
    if stream is not None and str(stream).lower() != expected:
        raise ParseError(SENSOR, "_path", f"expected {expected!r}, got {stream!r}")


def _sensor(document: dict[str, Any], sensor_id: str) -> SensorIdentity:
    return SensorIdentity(
        product="zeek",
        sensor_id=sensor_id,
        interface=optional_text(document.get("interface"), maximum=128),
    )
