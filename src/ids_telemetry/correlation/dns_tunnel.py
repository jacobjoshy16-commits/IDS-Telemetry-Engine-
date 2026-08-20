"""Behavioral DNS tunneling detector using query shape and volume features."""

from __future__ import annotations

import math
import statistics
from collections import Counter, OrderedDict
from datetime import datetime

from ids_telemetry.config import DnsTunnelSettings
from ids_telemetry.correlation.types import DetectionCandidate
from ids_telemetry.correlation.window import KeyedSlidingWindow
from ids_telemetry.models import (
    DNS_TUNNEL_TECHNIQUES,
    AlertSeverity,
    DetectionType,
    ZeekDnsQuery,
)

DnsKey = tuple[str, str]
_MULTI_LABEL_SUFFIXES = {
    "ac.uk",
    "co.jp",
    "co.uk",
    "com.au",
    "com.br",
    "com.cn",
    "com.mx",
    "net.au",
    "org.uk",
}
_SUSPICIOUS_QTYPES = {"NULL", "TXT", "TYPE10", "TYPE16"}


class DnsTunnelDetector:
    def __init__(self, settings: DnsTunnelSettings) -> None:
        self.settings = settings
        self._allowlist = tuple(
            domain.lower().rstrip(".") for domain in settings.allowlisted_domains
        )
        self._windows: KeyedSlidingWindow[DnsKey, ZeekDnsQuery] = KeyedSlidingWindow(
            window_seconds=settings.window_seconds,
            max_keys=settings.max_keys,
            max_values_per_key=settings.max_events_per_key,
            max_total_values=settings.max_total_events,
        )
        self._last_alert: OrderedDict[DnsKey, datetime] = OrderedDict()

    def observe(self, event: ZeekDnsQuery) -> DetectionCandidate | None:
        root_domain = registrable_domain(event.query)
        if self._is_allowlisted(root_domain):
            return None
        key: DnsKey = (str(event.src_ip), root_domain)
        current = self._windows.values(key)
        if any(entry.value.event_id == event.event_id for entry in current):
            return None
        entries = self._windows.add(key, event.observed_at, event)
        if len(entries) < self.settings.min_queries:
            return None

        queries = [entry.value.query for entry in entries]
        labels = [encoded_label(query, root_domain) for query in queries]
        entropies = [shannon_entropy(label) for label in labels]
        long_ratio = sum(
            len(query) >= self.settings.long_query_characters
            or len(label) >= self.settings.encoded_label_characters
            for query, label in zip(queries, labels, strict=True)
        ) / len(queries)
        entropy_ratio = sum(
            len(label) >= self.settings.encoded_label_characters
            and entropy >= self.settings.entropy_threshold
            for label, entropy in zip(labels, entropies, strict=True)
        ) / len(queries)
        unique_ratio = len(set(queries)) / len(queries)
        suspicious_type_ratio = sum(
            entry.value.qtype in _SUSPICIOUS_QTYPES for entry in entries
        ) / len(entries)
        negative_response_ratio = sum(
            (entry.value.rcode or "").upper() in {"NXDOMAIN", "SERVFAIL", "3", "2"}
            for entry in entries
        ) / len(entries)
        span_seconds = max(1.0, (entries[-1].timestamp - entries[0].timestamp).total_seconds())
        queries_per_minute = len(entries) * 60.0 / span_seconds
        rate_component = min(1.0, queries_per_minute / self.settings.query_rate_per_minute)
        response_component = max(suspicious_type_ratio, negative_response_ratio * 0.5)

        score = (
            0.27 * long_ratio
            + 0.25 * entropy_ratio
            + 0.20 * unique_ratio
            + 0.18 * rate_component
            + 0.10 * response_component
        )
        if score < self.settings.minimum_score:
            return None

        previous = self._last_alert.get(key)
        if previous is not None:
            self._last_alert.move_to_end(key)
            elapsed = (event.observed_at - previous).total_seconds()
            if 0 <= elapsed < self.settings.cooldown_seconds:
                return None
        self._last_alert[key] = event.observed_at
        self._last_alert.move_to_end(key)
        while len(self._last_alert) > self.settings.max_keys:
            self._last_alert.popitem(last=False)

        severity = AlertSeverity.HIGH if score >= 0.82 else AlertSeverity.MEDIUM
        return DetectionCandidate(
            detection_type=DetectionType.DNS_TUNNELING,
            title="DNS query behavior consistent with tunneling",
            description=(
                f"{event.src_ip} issued {len(entries)} high-variability queries for "
                f"{root_domain} at {queries_per_minute:.1f} queries per minute."
            ),
            severity=severity,
            confidence=round(min(score, 1.0), 4),
            first_seen=entries[0].timestamp,
            last_seen=entries[-1].timestamp,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            transport=event.transport,
            event_ids=tuple(entry.value.event_id for entry in entries[-64:]),
            evidence={
                "root_domain": root_domain,
                "query_count": len(entries),
                "queries_per_minute": round(queries_per_minute, 4),
                "average_query_length": round(statistics.fmean(map(len, queries)), 2),
                "maximum_label_length": max(map(len, labels)),
                "average_label_entropy": round(statistics.fmean(entropies), 6),
                "long_query_ratio": round(long_ratio, 6),
                "high_entropy_ratio": round(entropy_ratio, 6),
                "unique_query_ratio": round(unique_ratio, 6),
                "suspicious_qtype_ratio": round(suspicious_type_ratio, 6),
                "negative_response_ratio": round(negative_response_ratio, 6),
                "detector_score": round(score, 6),
            },
            mitre_attack=DNS_TUNNEL_TECHNIQUES,
            tags=("nsm", "dns", "tunneling", "zeek"),
            deduplication_key="|".join((DetectionType.DNS_TUNNELING.value, *key)),
        )

    def _is_allowlisted(self, domain: str) -> bool:
        return any(
            domain == allowed or domain.endswith(f".{allowed}") for allowed in self._allowlist
        )


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = Counter(value.lower())
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())


def registrable_domain(query: str) -> str:
    """Best-effort eTLD+1 extraction without a mutable public-suffix dependency."""

    labels = [label for label in query.lower().rstrip(".").split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    suffix = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if suffix in _MULTI_LABEL_SUFFIXES else suffix


def encoded_label(query: str, root_domain: str) -> str:
    suffix = f".{root_domain}"
    subdomain = query[: -len(suffix)] if query.endswith(suffix) else query
    labels = [label for label in subdomain.split(".") if label]
    return max(labels, key=len, default="")
