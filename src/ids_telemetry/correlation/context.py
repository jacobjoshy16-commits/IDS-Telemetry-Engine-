"""Temporal indexes and interfaces for cross-source correlation context."""

from __future__ import annotations

from collections import OrderedDict, deque
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Protocol, TypeVar

from ids_telemetry.models import EndpointAuthEvent, SuricataAlert

IpAddress = IPv4Address | IPv6Address
ContextRecord = TypeVar("ContextRecord", SuricataAlert, EndpointAuthEvent)


class AuthEventLookup(Protocol):
    async def search(
        self,
        *,
        endpoints: tuple[IpAddress, ...],
        start: datetime,
        end: datetime,
        limit: int,
    ) -> tuple[EndpointAuthEvent, ...]: ...


class NullAuthEventLookup:
    async def search(
        self,
        *,
        endpoints: tuple[IpAddress, ...],
        start: datetime,
        end: datetime,
        limit: int,
    ) -> tuple[EndpointAuthEvent, ...]:
        return ()


class TemporalContextIndex:
    """IP-keyed recent Suricata and endpoint-auth records."""

    def __init__(
        self,
        *,
        max_records_per_endpoint: int = 2_000,
        max_endpoints: int = 100_000,
    ) -> None:
        self._max_records = max_records_per_endpoint
        self._max_endpoints = max_endpoints
        self._suricata: OrderedDict[str, deque[SuricataAlert]] = OrderedDict()
        self._authentication: OrderedDict[str, deque[EndpointAuthEvent]] = OrderedDict()

    def add_suricata(self, event: SuricataAlert) -> None:
        for endpoint in {str(event.src_ip), str(event.dst_ip)}:
            self._append(self._suricata, endpoint, event)

    def add_authentication(self, event: EndpointAuthEvent) -> None:
        endpoints = {
            str(address) for address in (event.host_ip, event.source_ip) if address is not None
        }
        for endpoint in endpoints:
            self._append(self._authentication, endpoint, event)

    def find_suricata(
        self,
        *,
        endpoints: tuple[IpAddress, ...],
        start: datetime,
        end: datetime,
        limit: int,
    ) -> tuple[SuricataAlert, ...]:
        records = self._find(self._suricata, endpoints, start, end)
        return tuple(records[:limit])

    def find_authentication(
        self,
        *,
        endpoints: tuple[IpAddress, ...],
        start: datetime,
        end: datetime,
        limit: int,
    ) -> tuple[EndpointAuthEvent, ...]:
        records = self._find(self._authentication, endpoints, start, end)
        return tuple(records[:limit])

    @staticmethod
    def _find(
        index: dict[str, deque[ContextRecord]],
        endpoints: tuple[IpAddress, ...],
        start: datetime,
        end: datetime,
    ) -> list[ContextRecord]:
        by_id: dict[str, ContextRecord] = {}
        for endpoint in endpoints:
            for record in index.get(str(endpoint), ()):
                if start <= record.observed_at <= end:
                    by_id[record.event_id] = record
        return sorted(by_id.values(), key=lambda record: record.observed_at, reverse=True)

    def _append(
        self,
        index: OrderedDict[str, deque[ContextRecord]],
        endpoint: str,
        record: ContextRecord,
    ) -> None:
        window = index.get(endpoint)
        if window is None:
            window = deque()
            index[endpoint] = window
        else:
            index.move_to_end(endpoint)
        window.append(record)
        while len(window) > self._max_records:
            window.popleft()
        while len(index) > self._max_endpoints:
            index.popitem(last=False)
