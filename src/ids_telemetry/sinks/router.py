"""Document-type-aware routing to local JSON and OpenSearch sinks."""

from __future__ import annotations

from ids_telemetry.models import CorrelationAlert, MetricSnapshot, TelemetryEvent
from ids_telemetry.sinks.base import EventSink


class OutputRouter:
    def __init__(
        self,
        *,
        json_sink: EventSink,
        opensearch_sink: EventSink | None,
        include_normalized_events: bool,
        include_metric_snapshots: bool,
    ) -> None:
        self._json = json_sink
        self._opensearch = opensearch_sink
        self._include_events = include_normalized_events
        self._include_metrics = include_metric_snapshots

    async def emit_event(self, event: TelemetryEvent) -> None:
        if self._opensearch is not None:
            await self._opensearch.emit(event)
        if self._include_events:
            await self._json.emit(event)

    async def emit_alert(self, alert: CorrelationAlert) -> None:
        if self._opensearch is not None:
            await self._opensearch.emit(alert)
        await self._json.emit(alert)

    async def emit_metric(self, snapshot: MetricSnapshot) -> None:
        if self._opensearch is not None:
            await self._opensearch.emit(snapshot)
        if self._include_metrics:
            await self._json.emit(snapshot)

    async def close(self) -> None:
        if self._opensearch is not None:
            await self._opensearch.close()
        await self._json.close()
