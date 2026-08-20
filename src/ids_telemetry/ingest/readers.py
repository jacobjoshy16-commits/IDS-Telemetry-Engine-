"""Rotation-aware JSONL readers and event-time fixture replay."""

from __future__ import annotations

import asyncio
import heapq
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from ids_telemetry.metrics import EngineMetrics
from ids_telemetry.models import TelemetryEvent
from ids_telemetry.normalization import ParseError

logger = logging.getLogger(__name__)
Parser = Callable[[str], TelemetryEvent]


@dataclass(frozen=True, slots=True)
class SourceDefinition:
    sensor: str
    path: Path
    parser: Parser


async def follow_source(
    source: SourceDefinition,
    queue: asyncio.Queue[TelemetryEvent | object],
    *,
    from_beginning: bool,
    poll_interval_seconds: float,
    metrics: EngineMetrics,
) -> None:
    """Follow a file across truncate/create and inode-replacement rotations."""

    stream: TextIO | None = None
    inode: int | None = None
    line_number = 0
    first_open = True
    missing_logged = False
    try:
        while True:
            if stream is None:
                try:
                    stream = source.path.open("r", encoding="utf-8")
                    stat = source.path.stat()
                except FileNotFoundError:
                    if not missing_logged:
                        logger.warning(
                            "telemetry source is not present; waiting",
                            extra={"sensor": source.sensor, "path": str(source.path)},
                        )
                        missing_logged = True
                    await asyncio.sleep(poll_interval_seconds)
                    continue
                missing_logged = False
                inode = stat.st_ino
                line_number = 0
                if first_open and not from_beginning:
                    stream.seek(0, 2)
                first_open = False
                logger.info(
                    "opened telemetry source",
                    extra={"sensor": source.sensor, "path": str(source.path)},
                )

            line = stream.readline()
            if line:
                line_number += 1
                event = _parse_line(source, line, line_number, metrics)
                if event is not None:
                    await queue.put(event)
                continue

            try:
                stat = source.path.stat()
                replaced = inode is not None and stat.st_ino != inode
                truncated = stat.st_size < stream.tell()
            except FileNotFoundError:
                replaced = True
                truncated = False
            if replaced or truncated:
                stream.close()
                stream = None
                continue
            await asyncio.sleep(poll_interval_seconds)
    finally:
        if stream is not None:
            stream.close()


async def replay_sources(
    sources: tuple[SourceDefinition, ...],
    queue: asyncio.Queue[TelemetryEvent | object],
    *,
    metrics: EngineMetrics,
    events_per_second: float = 0.0,
) -> None:
    """K-way merge pre-sorted sensor logs and replay in event-time order."""

    iterators = [_iter_source(source, metrics) for source in sources]
    heap: list[tuple[object, int, TelemetryEvent, Iterator[TelemetryEvent]]] = []
    sequence = 0
    for iterator in iterators:
        try:
            event = next(iterator)
        except StopIteration:
            continue
        heapq.heappush(heap, (event.observed_at, sequence, event, iterator))
        sequence += 1

    delay = 1.0 / events_per_second if events_per_second > 0 else 0.0
    while heap:
        _, _, event, iterator = heapq.heappop(heap)
        await queue.put(event)
        if delay:
            await asyncio.sleep(delay)
        try:
            next_event = next(iterator)
        except StopIteration:
            continue
        heapq.heappush(heap, (next_event.observed_at, sequence, next_event, iterator))
        sequence += 1


def _iter_source(source: SourceDefinition, metrics: EngineMetrics) -> Iterator[TelemetryEvent]:
    with source.path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            event = _parse_line(source, line, line_number, metrics)
            if event is not None:
                yield event


def _parse_line(
    source: SourceDefinition,
    line: str,
    line_number: int,
    metrics: EngineMetrics,
) -> TelemetryEvent | None:
    if not line.strip():
        return None
    try:
        return source.parser(line)
    except ParseError as exc:
        metrics.record_parse_error(source.sensor)
        logger.warning(
            "rejected malformed sensor record",
            extra={
                "sensor": source.sensor,
                "path": str(source.path),
                "line_number": line_number,
                "field": exc.field,
                "reason": exc.reason,
            },
        )
        return None
