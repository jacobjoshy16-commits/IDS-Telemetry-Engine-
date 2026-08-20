"""Prometheus instrumentation and SIEM-indexable metric snapshots."""

from __future__ import annotations

import threading
import time
from collections import Counter as CounterMap
from datetime import UTC, datetime
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, start_http_server

from ids_telemetry.models import (
    CorrelationAlert,
    MetricSnapshot,
    SensorIdentity,
    TelemetryEvent,
)
from ids_telemetry.normalization import stable_event_id


class EngineMetrics:
    def __init__(self, *, service_name: str, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry(auto_describe=True)
        self._service_name = service_name
        self._started = time.monotonic()
        self._lock = threading.Lock()
        self._shadow: CounterMap[str] = CounterMap()
        self.events = Counter(
            "ids_telemetry_events_ingested_total",
            "Canonical telemetry events accepted by the engine.",
            ("sensor", "event_type"),
            registry=self.registry,
        )
        self.parse_errors = Counter(
            "ids_telemetry_parse_errors_total",
            "Sensor records rejected at the normalization boundary.",
            ("sensor",),
            registry=self.registry,
        )
        self.alerts = Counter(
            "ids_telemetry_correlation_alerts_total",
            "Behavioral correlation alerts generated.",
            ("detection_type", "severity"),
            registry=self.registry,
        )
        self.auth_lookup_errors = Counter(
            "ids_telemetry_auth_lookup_errors_total",
            "Failed OpenSearch endpoint-authentication context queries.",
            registry=self.registry,
        )
        self.processing_latency = Histogram(
            "ids_telemetry_event_processing_seconds",
            "Correlation and output-dispatch latency per normalized event.",
            buckets=(0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.05, 0.1, 0.5),
            registry=self.registry,
        )
        self.queue_depth = Gauge(
            "ids_telemetry_ingest_queue_depth",
            "Current number of normalized events waiting for correlation.",
            registry=self.registry,
        )
        self.build_info = Gauge(
            "ids_telemetry_build_info",
            "Static service build identity.",
            ("service", "version"),
            registry=self.registry,
        )
        self.build_info.labels(service=service_name, version="0.1.0").set(1)
        self._http_server: Any = None

    def start_http(self, *, host: str, port: int) -> None:
        self._http_server = start_http_server(port, addr=host, registry=self.registry)

    def record_event(self, event: TelemetryEvent) -> None:
        self.events.labels(sensor=event.sensor.product, event_type=event.kind.value).inc()
        self._increment("events.total")
        self._increment(f"events.{event.kind.value}")

    def record_parse_error(self, sensor: str) -> None:
        self.parse_errors.labels(sensor=sensor).inc()
        self._increment("parse_errors.total")
        self._increment(f"parse_errors.{sensor}")

    def record_alert(self, alert: CorrelationAlert) -> None:
        self.alerts.labels(
            detection_type=alert.detection_type.value,
            severity=alert.severity.value,
        ).inc()
        self._increment("alerts.total")
        self._increment(f"alerts.{alert.detection_type.value}")

    def record_auth_lookup_error(self) -> None:
        self.auth_lookup_errors.inc()
        self._increment("auth_lookup_errors.total")

    def set_queue_depth(self, value: int) -> None:
        self.queue_depth.set(value)

    def observe_processing(self, elapsed_seconds: float) -> None:
        self.processing_latency.observe(elapsed_seconds)

    def snapshot(self, *, sensor_id: str, interval_seconds: float) -> MetricSnapshot:
        now = datetime.now(UTC)
        with self._lock:
            counters = dict(self._shadow)
        return MetricSnapshot(
            event_id=stable_event_id("metric", self._service_name, now.isoformat()),
            observed_at=now,
            sensor=SensorIdentity(product="ids-telemetry-engine", sensor_id=sensor_id),
            interval_seconds=float(interval_seconds),
            counters=counters,
            gauges={
                "queue.depth": float(self.queue_depth._value.get()),
                "process.uptime_seconds": float(time.monotonic() - self._started),
            },
        )

    def _increment(self, key: str) -> None:
        with self._lock:
            self._shadow[key] += 1
