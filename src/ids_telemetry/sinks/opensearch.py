"""Asynchronous, bounded OpenSearch bulk indexing sink."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opensearchpy import OpenSearch

from ids_telemetry.config import OpenSearchSettings
from ids_telemetry.models import BaseTelemetryEvent, CorrelationAlert, MetricSnapshot

logger = logging.getLogger(__name__)
_STOP = object()


class OpenSearchBulkSink:
    def __init__(
        self,
        client: OpenSearch,
        settings: OpenSearchSettings,
        *,
        queue_size: int = 20_000,
    ) -> None:
        self._client = client
        self._settings = settings
        self._queue: asyncio.Queue[BaseTelemetryEvent | object] = asyncio.Queue(maxsize=queue_size)
        self._worker: asyncio.Task[None] | None = None
        self.failed_documents = 0
        self.indexed_documents = 0

    async def emit(self, document: BaseTelemetryEvent) -> None:
        if self._worker is None:
            self._worker = asyncio.create_task(self._run(), name="opensearch-bulk-sink")
        await self._queue.put(document)

    async def close(self) -> None:
        if self._worker is None:
            return
        await self._queue.put(_STOP)
        await self._worker
        self._worker = None

    async def _run(self) -> None:
        stopping = False
        while not stopping:
            first = await self._queue.get()
            if first is _STOP:
                self._queue.task_done()
                break
            batch = [first]
            deadline = asyncio.get_running_loop().time() + self._settings.flush_interval_seconds
            while len(batch) < self._settings.batch_size:
                timeout = deadline - asyncio.get_running_loop().time()
                if timeout <= 0:
                    break
                try:
                    item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                except TimeoutError:
                    break
                if item is _STOP:
                    self._queue.task_done()
                    stopping = True
                    break
                batch.append(item)
            await self._flush([item for item in batch if isinstance(item, BaseTelemetryEvent)])
            for _ in batch:
                self._queue.task_done()

    async def _flush(self, documents: list[BaseTelemetryEvent]) -> None:
        if not documents:
            return
        body: list[dict[str, Any]] = []
        for document in documents:
            body.append(
                {
                    "index": {
                        "_index": self._index_name(document),
                        "_id": document.event_id,
                    }
                }
            )
            body.append(document.model_dump(mode="json", exclude_none=True))

        error: Exception | None = None
        for attempt in range(self._settings.max_retries + 1):
            try:
                response = await asyncio.to_thread(
                    self._client.bulk,
                    body=body,
                    refresh=False,
                    request_timeout=self._settings.request_timeout_seconds,
                )
                if response.get("errors"):
                    failures = sum(
                        1
                        for result in response.get("items", [])
                        if result.get("index", {}).get("status", 500) >= 300
                    )
                    raise RuntimeError(f"OpenSearch bulk response contained {failures} failures")
                self.indexed_documents += len(documents)
                return
            except Exception as exc:
                error = exc
                if attempt < self._settings.max_retries:
                    await asyncio.sleep(min(8.0, 0.25 * (2**attempt)))
        self.failed_documents += len(documents)
        logger.error(
            "OpenSearch bulk indexing exhausted retries",
            extra={"document_count": len(documents), "error": repr(error)},
        )
        if self._settings.dead_letter_path is not None:
            await asyncio.to_thread(
                _append_dead_letters,
                self._settings.dead_letter_path,
                documents,
                error,
                self._index_name,
            )

    def _index_name(self, document: BaseTelemetryEvent) -> str:
        if isinstance(document, CorrelationAlert):
            prefix = self._settings.alerts_index_prefix
        elif isinstance(document, MetricSnapshot):
            prefix = self._settings.metrics_index_prefix
        else:
            prefix = self._settings.events_index_prefix
        return f"{prefix}-{_daily_suffix(document.observed_at)}"


def _daily_suffix(value: datetime) -> str:
    return value.strftime("%Y.%m.%d")


def _append_dead_letters(
    path: Path,
    documents: list[BaseTelemetryEvent],
    error: Exception | None,
    index_name: Callable[[BaseTelemetryEvent], str],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    failed_at = datetime.now(UTC).isoformat()
    error_message = repr(error)[:2048]
    with path.open("a", encoding="utf-8") as stream:
        for document in documents:
            stream.write(
                json.dumps(
                    {
                        "failed_at": failed_at,
                        "target_index": index_name(document),
                        "error": error_message,
                        "document": document.model_dump(mode="json", exclude_none=True),
                    },
                    separators=(",", ":"),
                )
                + "\n"
            )
