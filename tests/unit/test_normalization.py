from __future__ import annotations

from datetime import UTC

import pytest

from ids_telemetry.normalization import (
    ParseError,
    load_json_object,
    nested_get,
    optional_text,
    parse_bool,
    parse_float,
    parse_int,
    parse_ip,
    parse_optional_float,
    parse_optional_int,
    parse_optional_ip,
    parse_timestamp,
    require_text,
    stable_event_id,
)


def test_timestamp_accepts_epoch_and_aware_iso() -> None:
    epoch = parse_timestamp(1_700_000_000.0, sensor="test")
    iso = parse_timestamp("2023-11-14T22:13:20Z", sensor="test")
    assert epoch == iso
    assert epoch.tzinfo is UTC


def test_timestamp_rejects_naive_iso() -> None:
    with pytest.raises(ParseError, match="timezone offset"):
        parse_timestamp("2026-01-01T01:02:03", sensor="test")


def test_scalar_coercion_is_explicit_and_bounded() -> None:
    assert parse_int("443", sensor="test", field="port", minimum=0, maximum=65535) == 443
    assert parse_bool("yes", sensor="test", field="flag") is True
    assert str(parse_ip("192.0.2.1", sensor="test", field="ip")) == "192.0.2.1"
    with pytest.raises(ParseError, match="must be <= 65535"):
        parse_int(65536, sensor="test", field="port", maximum=65535)
    with pytest.raises(ParseError, match="boolean is not an integer"):
        parse_int(True, sensor="test", field="number")


def test_nested_get_supports_flat_ecs_and_nested_objects() -> None:
    assert nested_get({"host.ip": "192.0.2.4"}, "host.ip") == "192.0.2.4"
    assert nested_get({"host": {"ip": "192.0.2.5"}}, "host.ip") == "192.0.2.5"
    assert nested_get({}, "host.ip") is None


def test_stable_id_is_namespaced_and_unambiguous() -> None:
    assert stable_event_id("event", "ab", "c") != stable_event_id("event", "a", "bc")
    assert stable_event_id("event", 1) == stable_event_id("event", 1)


def test_json_and_timestamp_error_paths_are_explicit() -> None:
    with pytest.raises(ParseError, match="top-level value"):
        load_json_object("[]", sensor="test")
    assert parse_timestamp("1700000000", sensor="test").tzinfo is UTC
    for value in (True, "", object()):
        with pytest.raises(ParseError):
            parse_timestamp(value, sensor="test")


def test_optional_and_float_normalizers_cover_missing_values() -> None:
    assert parse_optional_ip("-", sensor="test", field="ip") is None
    assert parse_optional_int(None, sensor="test", field="number") is None
    assert parse_optional_float("(empty)", sensor="test", field="number") is None
    assert parse_float("1.25", sensor="test", field="number", minimum=1.0) == 1.25
    with pytest.raises(ParseError, match="boolean is not a number"):
        parse_float(True, sensor="test", field="number")
    with pytest.raises(ParseError, match="must be >= 2"):
        parse_float(1, sensor="test", field="number", minimum=2)
    with pytest.raises(ParseError, match="must be finite"):
        parse_float("nan", sensor="test", field="number")


def test_boolean_and_text_normalizers_reject_ambiguous_input() -> None:
    assert parse_bool(None, sensor="test", field="flag", default=True) is True
    assert parse_bool(0, sensor="test", field="flag") is False
    assert parse_bool("NO", sensor="test", field="flag") is False
    with pytest.raises(ParseError, match="expected boolean"):
        parse_bool("perhaps", sensor="test", field="flag")
    with pytest.raises(ParseError, match="expected string"):
        require_text(7, sensor="test", field="text")
    with pytest.raises(ParseError, match="value is missing"):
        require_text("-", sensor="test", field="text")
    with pytest.raises(ParseError, match="exceeds 2"):
        require_text("long", sensor="test", field="text", maximum=2)
    assert optional_text(None) is None
    assert optional_text("abcdef", maximum=3) == "abc"


def test_ip_and_integer_type_errors_are_wrapped() -> None:
    with pytest.raises(ParseError, match="expected string"):
        parse_ip(123, sensor="test", field="ip")
    with pytest.raises(ParseError):
        parse_ip("not-an-ip", sensor="test", field="ip")
    with pytest.raises(ParseError, match="expected integer"):
        parse_int(1.5, sensor="test", field="number")
    with pytest.raises(ParseError, match="must be >= 1"):
        parse_int(0, sensor="test", field="number", minimum=1)
