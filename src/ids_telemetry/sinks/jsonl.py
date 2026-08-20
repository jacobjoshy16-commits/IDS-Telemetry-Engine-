"""Canonical newline-delimited JSON sink for stdout or durable local output."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TextIO

from ids_telemetry.models import BaseTelemetryEvent


class JsonlSink:
    def __init__(self, path: Path | None) -> None:
        self._owns_stream = path is not None
        if path is None:
            self._stream: TextIO = sys.stdout
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._stream = path.open("a", encoding="utf-8", buffering=1)
        self._lock = asyncio.Lock()

    async def emit(self, document: BaseTelemetryEvent) -> None:
        payload = document.model_dump_json(exclude_none=True) + "\n"
        async with self._lock:
            self._stream.write(payload)
            self._stream.flush()

    async def close(self) -> None:
        if self._owns_stream:
            self._stream.close()
