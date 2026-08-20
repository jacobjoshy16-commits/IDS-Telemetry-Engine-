"""Explicit coercion helpers for the untrusted sensor boundary."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any


class ParseError(ValueError):
    """A sensor record could not be converted into the canonical schema."""

    def __init__(self, sensor: str, field: str, reason: str) -> None:
        self.sensor = sensor
        self.field = field
        self.reason = reason
        super().__init__(f"{sensor}: invalid {field}: {reason}")


def load_json_object(line: str | bytes, *, sensor: str) -> dict[str, Any]:
    try:
        value = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ParseError(sensor, "json", str(exc)) from exc
    if not isinstance(value, dict):
        raise ParseError(sensor, "json", "top-level value must be an object")
    return value


def parse_timestamp(value: Any, *, sensor: str, field: str = "timestamp") -> datetime:
    if isinstance(value, bool):
        raise ParseError(sensor, field, "boolean is not a timestamp")
    try:
        if isinstance(value, (int, float)):
            parsed = datetime.fromtimestamp(float(value), tz=UTC)
        elif isinstance(value, str):
            candidate = value.strip()
            if not candidate:
                raise ValueError("empty timestamp")
            if _looks_numeric(candidate):
                parsed = datetime.fromtimestamp(float(candidate), tz=UTC)
            else:
                if candidate.endswith(("Z", "z")):
                    candidate = candidate[:-1] + "+00:00"
                parsed = datetime.fromisoformat(candidate)
        else:
            raise TypeError(f"expected ISO-8601 string or epoch, got {type(value).__name__}")
    except (OverflowError, TypeError, ValueError, OSError) as exc:
        raise ParseError(sensor, field, str(exc)) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ParseError(sensor, field, "timezone offset is required")
    return parsed.astimezone(UTC)


def parse_ip(value: Any, *, sensor: str, field: str) -> IPv4Address | IPv6Address:
    if not isinstance(value, str):
        raise ParseError(sensor, field, f"expected string, got {type(value).__name__}")
    try:
        return ip_address(value.strip())
    except ValueError as exc:
        raise ParseError(sensor, field, str(exc)) from exc


def parse_optional_ip(value: Any, *, sensor: str, field: str) -> IPv4Address | IPv6Address | None:
    if is_missing(value):
        return None
    return parse_ip(value, sensor=sensor, field=field)


def parse_int(
    value: Any,
    *,
    sensor: str,
    field: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool):
        raise ParseError(sensor, field, "boolean is not an integer")
    try:
        if isinstance(value, int):
            parsed = value
        elif isinstance(value, str) and value.strip():
            parsed = int(value, 10)
        else:
            raise TypeError(f"expected integer, got {type(value).__name__}")
    except (TypeError, ValueError) as exc:
        raise ParseError(sensor, field, str(exc)) from exc
    if minimum is not None and parsed < minimum:
        raise ParseError(sensor, field, f"must be >= {minimum}")
    if maximum is not None and parsed > maximum:
        raise ParseError(sensor, field, f"must be <= {maximum}")
    return parsed


def parse_optional_int(
    value: Any,
    *,
    sensor: str,
    field: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int | None:
    if is_missing(value):
        return None
    return parse_int(
        value,
        sensor=sensor,
        field=field,
        minimum=minimum,
        maximum=maximum,
    )


def parse_float(value: Any, *, sensor: str, field: str, minimum: float | None = None) -> float:
    if isinstance(value, bool):
        raise ParseError(sensor, field, "boolean is not a number")
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip()):
            parsed = float(value)
        else:
            raise TypeError(f"expected number, got {type(value).__name__}")
    except (TypeError, ValueError) as exc:
        raise ParseError(sensor, field, str(exc)) from exc
    if not math.isfinite(parsed):
        raise ParseError(sensor, field, "must be finite")
    if minimum is not None and parsed < minimum:
        raise ParseError(sensor, field, f"must be >= {minimum}")
    return parsed


def parse_optional_float(
    value: Any, *, sensor: str, field: str, minimum: float | None = None
) -> float | None:
    if is_missing(value):
        return None
    return parse_float(value, sensor=sensor, field=field, minimum=minimum)


def parse_bool(value: Any, *, sensor: str, field: str, default: bool = False) -> bool:
    if is_missing(value):
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "t", "yes", "1"}:
            return True
        if lowered in {"false", "f", "no", "0"}:
            return False
    raise ParseError(sensor, field, f"expected boolean, got {value!r}")


def require_text(
    value: Any,
    *,
    sensor: str,
    field: str,
    maximum: int | None = None,
) -> str:
    if not isinstance(value, str):
        raise ParseError(sensor, field, f"expected string, got {type(value).__name__}")
    parsed = value.strip()
    if not parsed or parsed == "-":
        raise ParseError(sensor, field, "value is missing")
    if maximum is not None and len(parsed) > maximum:
        raise ParseError(sensor, field, f"exceeds {maximum} characters")
    return parsed


def optional_text(value: Any, *, maximum: int | None = None) -> str | None:
    if is_missing(value):
        return None
    parsed = str(value).strip()
    if maximum is not None:
        parsed = parsed[:maximum]
    return parsed or None


def is_missing(value: Any) -> bool:
    return value is None or value == "-" or value == "(empty)"


def stable_event_id(namespace: str, *parts: object) -> str:
    """Produce a compact deterministic id so replay is naturally idempotent."""

    digest = hashlib.blake2b(digest_size=16, person=b"ids-telemetry-v1")
    for part in parts:
        encoded = str(part).encode("utf-8", errors="replace")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return f"{namespace}-{digest.hexdigest()}"


def nested_get(document: dict[str, Any], *paths: str) -> Any:
    """Return the first direct dotted key or nested object path that exists."""

    for path in paths:
        if path in document:
            return document[path]
        current: Any = document
        found = True
        for component in path.split("."):
            if not isinstance(current, dict) or component not in current:
                found = False
                break
            current = current[component]
        if found:
            return current
    return None


def _looks_numeric(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True
