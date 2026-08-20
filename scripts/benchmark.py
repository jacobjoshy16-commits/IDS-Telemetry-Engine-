#!/usr/bin/env python3
"""Deterministic parser + sliding-window correlation throughput benchmark."""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from pathlib import Path

from ids_telemetry.config import BeaconSettings
from ids_telemetry.correlation.beacon import BeaconDetector
from ids_telemetry.parsers.zeek import parse_zeek_conn_line


def connection_line(index: int) -> str:
    key = index % 64
    source = f"10.1.{key // 254}.{key % 254 + 1}"
    destination = f"198.51.100.{key % 250 + 1}"
    # Each key returns every 32 seconds with small deterministic payload variation.
    timestamp = 1_700_000_000.0 + index * 0.5
    return (
        f'{{"_path":"conn","ts":{timestamp},"uid":"Cbench{index:012d}",'
        f'"id.orig_h":"{source}","id.orig_p":{40000 + index % 20000},'
        f'"id.resp_h":"{destination}","id.resp_p":443,"proto":"tcp",'
        f'"service":"ssl","duration":0.12,"orig_bytes":{96 + index % 32},'
        f'"resp_bytes":{80 + index % 16},"conn_state":"SF","missed_bytes":0,'
        f'"orig_pkts":4,"resp_pkts":3}}'
    )


def run_benchmark(events: int, warmup: int) -> dict[str, object]:
    detector = BeaconDetector(BeaconSettings())
    for index in range(warmup):
        detector.observe(parse_zeek_conn_line(connection_line(index), sensor_id="benchmark"))

    alerts = 0
    started = time.perf_counter()
    for index in range(warmup, warmup + events):
        event = parse_zeek_conn_line(connection_line(index), sensor_id="benchmark")
        alerts += detector.observe(event) is not None
    elapsed = time.perf_counter() - started
    return {
        "scope": "Suricata/Zeek-style JSON decode, strict Pydantic normalization, and beacon window update; excludes network and OpenSearch I/O",
        "events": events,
        "warmup_events": warmup,
        "elapsed_seconds": round(elapsed, 6),
        "events_per_second": round(events / elapsed, 2),
        "alerts_generated": alerts,
        "python": platform.python_version(),
        "platform": platform.platform(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=100_000)
    parser.add_argument("--warmup", type=int, default=5_000)
    parser.add_argument(
        "--assert-eps",
        type=float,
        default=0.0,
        help="Exit non-zero when measured throughput is below this threshold.",
    )
    parser.add_argument("--json-output", type=Path)
    arguments = parser.parse_args()
    if arguments.events <= 0 or arguments.warmup < 0 or arguments.assert_eps < 0:
        parser.error("events must be positive; warmup and assert-eps must be non-negative")

    result = run_benchmark(arguments.events, arguments.warmup)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if arguments.json_output is not None:
        arguments.json_output.parent.mkdir(parents=True, exist_ok=True)
        arguments.json_output.write_text(rendered + "\n", encoding="utf-8")
    if float(result["events_per_second"]) < arguments.assert_eps:
        print(
            f"throughput {result['events_per_second']} EPS is below required {arguments.assert_eps} EPS",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
