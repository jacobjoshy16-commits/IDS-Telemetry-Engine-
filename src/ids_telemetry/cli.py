"""Command-line interface for daemon operation, replay, and schema validation."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Callable
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from ids_telemetry import __version__
from ids_telemetry.config import (
    EngineSettings,
    MetricsSettings,
    SourceSettings,
)
from ids_telemetry.daemon import run_daemon
from ids_telemetry.logging import configure_logging
from ids_telemetry.models import CorrelationAlert, TelemetryEvent
from ids_telemetry.normalization import ParseError
from ids_telemetry.parsers import (
    parse_endpoint_auth_line,
    parse_suricata_line,
    parse_zeek_conn_line,
    parse_zeek_dns_line,
)

Parser = Callable[[str], TelemetryEvent]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ids-telemetry",
        description="Normalize and correlate Suricata, Zeek, and endpoint telemetry.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="Run rotation-aware sensor file followers")
    _add_source_arguments(run)
    run.add_argument(
        "--from-beginning",
        action="store_true",
        help="Read existing records before following newly appended records.",
    )
    run.add_argument(
        "--output", type=Path, help="Write alerts to this JSONL file (stdout by default)."
    )
    run.add_argument(
        "--include-events", action="store_true", help="Also write normalized events to JSONL."
    )
    run.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"))

    replay = subparsers.add_parser(
        "replay", help="Replay pre-sorted JSONL logs in merged event-time order"
    )
    _add_source_arguments(replay)
    replay.add_argument("--output", type=Path, help="Write output JSONL (stdout by default).")
    replay.add_argument(
        "--include-events", action="store_true", help="Include normalized records in output."
    )
    replay.add_argument(
        "--rate",
        type=float,
        default=0.0,
        help="Replay events per second; 0 processes as fast as possible.",
    )
    replay.add_argument(
        "--opensearch",
        action="store_true",
        help="Enable the environment-configured OpenSearch output and auth lookup.",
    )
    replay.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"))

    validate = subparsers.add_parser("validate", help="Validate one sensor JSONL file")
    validate.add_argument(
        "sensor",
        choices=("suricata", "zeek-conn", "zeek-dns", "endpoint-auth"),
    )
    validate.add_argument("path", type=Path)

    schema = subparsers.add_parser("schema", help="Print canonical JSON Schemas")
    schema.add_argument("model", choices=("telemetry", "alert"), default="telemetry", nargs="?")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.command == "validate":
        return _validate(arguments.sensor, arguments.path)
    if arguments.command == "schema":
        adapter = (
            TypeAdapter(TelemetryEvent)
            if arguments.model == "telemetry"
            else TypeAdapter(CorrelationAlert)
        )
        print(json.dumps(adapter.json_schema(), indent=2, sort_keys=True))
        return 0

    try:
        settings = _settings_for_command(arguments)
    except ValidationError as exc:
        print(f"configuration error:\n{exc}", file=sys.stderr)
        return 2
    configure_logging(settings.log_level)
    try:
        asyncio.run(
            run_daemon(
                settings,
                replay_events_per_second=(arguments.rate if arguments.command == "replay" else 0.0),
            )
        )
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"fatal: {exc}", file=sys.stderr)
        return 1
    return 0


def _settings_for_command(arguments: argparse.Namespace) -> EngineSettings:
    supplied_paths = {
        "suricata_path": arguments.suricata,
        "zeek_conn_path": arguments.zeek_conn,
        "zeek_dns_path": arguments.zeek_dns,
        "endpoint_auth_path": arguments.endpoint_auth,
    }
    if any(supplied_paths.values()):
        source = SourceSettings(
            **supplied_paths,
            follow=arguments.command == "run",
            from_beginning=(arguments.from_beginning if arguments.command == "run" else True),
        )
        settings = EngineSettings(source=source)
    else:
        settings = EngineSettings()
        if arguments.command == "replay":
            settings = settings.model_copy(
                update={
                    "source": settings.source.model_copy(
                        update={"follow": False, "from_beginning": True}
                    )
                }
            )

    output = settings.output.model_copy(
        update={
            "jsonl_path": arguments.output if arguments.output else settings.output.jsonl_path,
            "include_normalized_events": bool(arguments.include_events)
            or settings.output.include_normalized_events,
        }
    )
    updates: dict[str, object] = {"output": output}
    if arguments.log_level:
        updates["log_level"] = arguments.log_level
    if arguments.command == "replay":
        updates["metrics"] = MetricsSettings(enabled=False)
        if arguments.opensearch:
            updates["opensearch"] = settings.opensearch.model_copy(update={"enabled": True})
        if arguments.rate < 0:
            raise ValidationError.from_exception_data(
                "ReplaySettings",
                [
                    {
                        "type": "greater_than_equal",
                        "loc": ("rate",),
                        "input": arguments.rate,
                        "ctx": {"ge": 0},
                    }
                ],
            )
        if arguments.output and arguments.output.exists():
            arguments.output.unlink()
    return settings.model_copy(update=updates)


def _add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--suricata", type=Path, help="Suricata EVE alert JSONL path.")
    parser.add_argument("--zeek-conn", type=Path, help="Zeek conn.log JSON path.")
    parser.add_argument("--zeek-dns", type=Path, help="Zeek dns.log JSON path.")
    parser.add_argument("--endpoint-auth", type=Path, help="Endpoint auth JSONL path.")


def _validate(sensor: str, path: Path) -> int:
    parsers: dict[str, Parser] = {
        "suricata": parse_suricata_line,
        "zeek-conn": parse_zeek_conn_line,
        "zeek-dns": parse_zeek_dns_line,
        "endpoint-auth": parse_endpoint_auth_line,
    }
    valid = 0
    invalid = 0
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    parsers[sensor](line)
                    valid += 1
                except ParseError as exc:
                    invalid += 1
                    print(
                        json.dumps(
                            {
                                "line": line_number,
                                "field": exc.field,
                                "reason": exc.reason,
                            }
                        ),
                        file=sys.stderr,
                    )
    except OSError as exc:
        print(f"cannot read {path}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"path": str(path), "sensor": sensor, "valid": valid, "invalid": invalid}))
    return 1 if invalid else 0
