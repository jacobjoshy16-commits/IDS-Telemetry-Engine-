"""Async daemon lifecycle, backpressure, and source-to-sink pipeline."""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from contextlib import suppress
from functools import partial
from typing import Any, TypeGuard

from ids_telemetry.config import EngineSettings
from ids_telemetry.correlation.engine import CorrelationEngine
from ids_telemetry.ingest.readers import SourceDefinition, follow_source, replay_sources
from ids_telemetry.metrics import EngineMetrics
from ids_telemetry.models import (
    EndpointAuthEvent,
    SuricataAlert,
    TelemetryEvent,
    ZeekConnection,
    ZeekDnsQuery,
)
from ids_telemetry.opensearch.client import OpenSearchAuthEventLookup, create_client
from ids_telemetry.parsers import (
    parse_endpoint_auth_line,
    parse_suricata_line,
    parse_zeek_conn_line,
    parse_zeek_dns_line,
)
from ids_telemetry.sinks.jsonl import JsonlSink
from ids_telemetry.sinks.opensearch import OpenSearchBulkSink
from ids_telemetry.sinks.router import OutputRouter

logger = logging.getLogger(__name__)
_STOP = object()


class TelemetryDaemon:
    def __init__(
        self,
        *,
        settings: EngineSettings,
        engine: CorrelationEngine,
        metrics: EngineMetrics,
        outputs: OutputRouter,
        replay_events_per_second: float = 0.0,
    ) -> None:
        self.settings = settings
        self.engine = engine
        self.metrics = metrics
        self.outputs = outputs
        self.replay_events_per_second = replay_events_per_second
        self.queue: asyncio.Queue[TelemetryEvent | object] = asyncio.Queue(
            maxsize=settings.queue_size
        )
        self._shutdown = asyncio.Event()

    def request_shutdown(self) -> None:
        self._shutdown.set()

    async def run(self) -> None:
        sources = _source_definitions(self.settings)
        consumer = asyncio.create_task(self._consume(), name="correlation-consumer")
        snapshot_task: asyncio.Task[None] | None = None
        if self.settings.metrics.enabled:
            snapshot_task = asyncio.create_task(self._snapshot_loop(), name="metric-snapshots")
        producers: list[asyncio.Task[None]] = []
        clean_pipeline = False
        try:
            if self.settings.source.follow:
                for source in sources:
                    producers.append(
                        asyncio.create_task(
                            follow_source(
                                source,
                                self.queue,
                                from_beginning=self.settings.source.from_beginning,
                                poll_interval_seconds=self.settings.source.poll_interval_seconds,
                                metrics=self.metrics,
                            ),
                            name=f"tail-{source.sensor}",
                        )
                    )
                await self._wait_live(producers, consumer)
                for producer in producers:
                    producer.cancel()
                await asyncio.gather(*producers, return_exceptions=True)
                await self._wait_for_drain(consumer)
            else:
                await replay_sources(
                    sources,
                    self.queue,
                    metrics=self.metrics,
                    events_per_second=self.replay_events_per_second,
                )
                await self._wait_for_drain(consumer)
            clean_pipeline = True
        finally:
            for producer in producers:
                if not producer.done():
                    producer.cancel()
            if producers:
                await asyncio.gather(*producers, return_exceptions=True)
            if not consumer.done():
                if clean_pipeline:
                    await self.queue.put(_STOP)
                    await consumer
                else:
                    consumer.cancel()
                    await asyncio.gather(consumer, return_exceptions=True)
            elif not consumer.cancelled():
                error = consumer.exception()
                if error is not None and clean_pipeline:
                    raise error
            if snapshot_task is not None:
                snapshot_task.cancel()
                await asyncio.gather(snapshot_task, return_exceptions=True)
            await self.outputs.close()

    async def _wait_live(
        self,
        producers: list[asyncio.Task[None]],
        consumer: asyncio.Task[None],
    ) -> None:
        shutdown_wait = asyncio.create_task(self._shutdown.wait(), name="shutdown-signal")
        watched: list[asyncio.Task[Any]] = [shutdown_wait, consumer, *producers]
        done, _ = await asyncio.wait(watched, return_when=asyncio.FIRST_COMPLETED)
        if shutdown_wait in done:
            logger.info("shutdown requested; draining telemetry queue")
            return
        shutdown_wait.cancel()
        await asyncio.gather(shutdown_wait, return_exceptions=True)
        for task in done:
            if task is consumer:
                await consumer
                raise RuntimeError("correlation consumer stopped unexpectedly")
            await task
            raise RuntimeError(f"telemetry producer {task.get_name()} stopped unexpectedly")

    async def _wait_for_drain(self, consumer: asyncio.Task[None]) -> None:
        join_task = asyncio.create_task(self.queue.join(), name="ingest-queue-drain")
        done, _ = await asyncio.wait((join_task, consumer), return_when=asyncio.FIRST_COMPLETED)
        if consumer in done:
            join_task.cancel()
            await asyncio.gather(join_task, return_exceptions=True)
            await consumer
            raise RuntimeError("correlation consumer stopped before queue drain")
        await join_task

    async def _consume(self) -> None:
        last_lookup_error_count = self.engine.auth_lookup_errors
        while True:
            item = await self.queue.get()
            if item is _STOP:
                self.queue.task_done()
                return
            if not _is_telemetry_event(item):
                self.queue.task_done()
                raise TypeError(f"unexpected queue item: {type(item).__name__}")
            started = time.perf_counter()
            try:
                self.metrics.record_event(item)
                await self.outputs.emit_event(item)
                alerts = await self.engine.process(item)
                for alert in alerts:
                    self.metrics.record_alert(alert)
                    await self.outputs.emit_alert(alert)
                while last_lookup_error_count < self.engine.auth_lookup_errors:
                    self.metrics.record_auth_lookup_error()
                    last_lookup_error_count += 1
            finally:
                self.metrics.observe_processing(time.perf_counter() - started)
                self.queue.task_done()
                self.metrics.set_queue_depth(self.queue.qsize())

    async def _snapshot_loop(self) -> None:
        interval = self.settings.metrics.snapshot_interval_seconds
        while True:
            await asyncio.sleep(interval)
            snapshot = self.metrics.snapshot(
                sensor_id=self.settings.sensor_id,
                interval_seconds=interval,
            )
            await self.outputs.emit_metric(snapshot)


async def run_daemon(
    settings: EngineSettings,
    *,
    replay_events_per_second: float = 0.0,
) -> None:
    metrics = EngineMetrics(service_name=settings.service_name)
    if settings.metrics.enabled:
        metrics.start_http(host=settings.metrics.bind_host, port=settings.metrics.port)
        logger.info(
            "metrics endpoint started",
            extra={"host": settings.metrics.bind_host, "port": settings.metrics.port},
        )

    client = create_client(settings.opensearch) if settings.opensearch.enabled else None
    auth_lookup = (
        OpenSearchAuthEventLookup(client, settings.opensearch) if client is not None else None
    )
    engine = CorrelationEngine(
        settings.correlation,
        sensor_id=settings.sensor_id,
        auth_lookup=auth_lookup,
    )
    opensearch_sink = (
        OpenSearchBulkSink(client, settings.opensearch, queue_size=settings.queue_size)
        if client is not None
        else None
    )
    outputs = OutputRouter(
        json_sink=JsonlSink(settings.output.jsonl_path),
        opensearch_sink=opensearch_sink,
        include_normalized_events=settings.output.include_normalized_events,
        include_metric_snapshots=settings.output.include_metric_snapshots,
    )
    daemon = TelemetryDaemon(
        settings=settings,
        engine=engine,
        metrics=metrics,
        outputs=outputs,
        replay_events_per_second=replay_events_per_second,
    )
    loop = asyncio.get_running_loop()
    for shutdown_signal in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError):  # pragma: no cover - Windows compatibility
            loop.add_signal_handler(shutdown_signal, daemon.request_shutdown)
    try:
        await daemon.run()
    finally:
        if client is not None:
            client.close()


def _source_definitions(settings: EngineSettings) -> tuple[SourceDefinition, ...]:
    source = settings.source
    definitions: list[SourceDefinition] = []
    if source.suricata_path is not None:
        definitions.append(
            SourceDefinition(
                sensor="suricata",
                path=source.suricata_path,
                parser=partial(parse_suricata_line, sensor_id="suricata-01"),
            )
        )
    if source.zeek_conn_path is not None:
        definitions.append(
            SourceDefinition(
                sensor="zeek.conn",
                path=source.zeek_conn_path,
                parser=partial(parse_zeek_conn_line, sensor_id="zeek-01"),
            )
        )
    if source.zeek_dns_path is not None:
        definitions.append(
            SourceDefinition(
                sensor="zeek.dns",
                path=source.zeek_dns_path,
                parser=partial(parse_zeek_dns_line, sensor_id="zeek-01"),
            )
        )
    if source.endpoint_auth_path is not None:
        definitions.append(
            SourceDefinition(
                sensor="endpoint.auth",
                path=source.endpoint_auth_path,
                parser=partial(parse_endpoint_auth_line, sensor_id="endpoint-01"),
            )
        )
    return tuple(definitions)


def _is_telemetry_event(value: object) -> TypeGuard[TelemetryEvent]:
    return isinstance(value, (SuricataAlert, ZeekConnection, ZeekDnsQuery, EndpointAuthEvent))
