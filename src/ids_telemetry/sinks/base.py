"""Output sink contracts and fan-out implementation."""

from __future__ import annotations

from typing import Protocol

from ids_telemetry.models import BaseTelemetryEvent


class EventSink(Protocol):
    async def emit(self, document: BaseTelemetryEvent) -> None: ...

    async def close(self) -> None: ...


class CompositeSink:
    def __init__(self, sinks: tuple[EventSink, ...]) -> None:
        self._sinks = sinks

    async def emit(self, document: BaseTelemetryEvent) -> None:
        for sink in self._sinks:
            await sink.emit(document)

    async def close(self) -> None:
        for sink in reversed(self._sinks):
            await sink.close()


class NullSink:
    async def emit(self, document: BaseTelemetryEvent) -> None:
        del document

    async def close(self) -> None:
        return None
