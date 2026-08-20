"""OpenSearch client construction and endpoint authentication lookups."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any

from opensearchpy import OpenSearch

from ids_telemetry.config import OpenSearchSettings
from ids_telemetry.models import EndpointAuthEvent
from ids_telemetry.normalization import ParseError
from ids_telemetry.parsers.endpoint import parse_endpoint_auth

logger = logging.getLogger(__name__)


def create_client(settings: OpenSearchSettings) -> OpenSearch:
    auth = None
    if settings.username is not None and settings.password is not None:
        auth = (settings.username, settings.password.get_secret_value())
    return OpenSearch(
        hosts=list(settings.hosts),
        http_auth=auth,
        verify_certs=settings.verify_certs,
        ca_certs=str(settings.ca_certs) if settings.ca_certs else None,
        timeout=settings.request_timeout_seconds,
        max_retries=settings.max_retries,
        retry_on_timeout=True,
    )


class OpenSearchAuthEventLookup:
    """Queries ECS authentication documents around an anomalous network window."""

    def __init__(self, client: OpenSearch, settings: OpenSearchSettings) -> None:
        self._client = client
        self._index = settings.auth_index_pattern
        self._request_timeout = settings.request_timeout_seconds

    async def search(
        self,
        *,
        endpoints: tuple[Any, ...],
        start: datetime,
        end: datetime,
        limit: int,
    ) -> tuple[EndpointAuthEvent, ...]:
        endpoint_values = [str(endpoint) for endpoint in endpoints]
        body = {
            "size": limit,
            "track_total_hits": False,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start.isoformat(),
                                    "lte": end.isoformat(),
                                }
                            }
                        }
                    ],
                    "should": [
                        {"terms": {"host.ip": endpoint_values}},
                        {"terms": {"source.ip": endpoint_values}},
                        {"terms": {"client.ip": endpoint_values}},
                    ],
                    "minimum_should_match": 1,
                }
            },
        }
        response = await asyncio.to_thread(
            self._client.search,
            index=self._index,
            body=body,
            request_timeout=self._request_timeout,
        )
        parsed: list[EndpointAuthEvent] = []
        hits = response.get("hits", {}).get("hits", [])
        for hit in hits:
            source = dict(hit.get("_source") or {})
            source.setdefault("_id", hit.get("_id"))
            try:
                parsed.append(parse_endpoint_auth(source, sensor_id="opensearch-auth"))
            except ParseError:
                logger.warning(
                    "ignored malformed OpenSearch authentication document",
                    extra={"document_id": hit.get("_id")},
                    exc_info=True,
                )
        return tuple(parsed)
