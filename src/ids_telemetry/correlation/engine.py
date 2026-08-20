"""Detector orchestration and cross-source alert enrichment."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from ids_telemetry.config import CorrelationSettings
from ids_telemetry.correlation.beacon import BeaconDetector
from ids_telemetry.correlation.context import (
    AuthEventLookup,
    NullAuthEventLookup,
    TemporalContextIndex,
)
from ids_telemetry.correlation.dns_tunnel import DnsTunnelDetector
from ids_telemetry.correlation.types import DetectionCandidate
from ids_telemetry.models import (
    NETWORK_MONITORING_CONTROLS,
    AlertSeverity,
    AuthEvidence,
    AuthOutcome,
    CorrelationAlert,
    EndpointAuthEvent,
    SensorIdentity,
    SuricataAlert,
    SuricataEvidence,
    TelemetryEvent,
    ZeekConnection,
    ZeekDnsQuery,
)
from ids_telemetry.normalization import stable_event_id

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = (
    AlertSeverity.LOW,
    AlertSeverity.MEDIUM,
    AlertSeverity.HIGH,
    AlertSeverity.CRITICAL,
)


class CorrelationEngine:
    """Stateful event-time correlator.

    ``process`` is async because authentication context may be queried from OpenSearch
    only when a network detector emits a candidate; ordinary event processing remains
    CPU-local and allocation-bounded.
    """

    def __init__(
        self,
        settings: CorrelationSettings,
        *,
        sensor_id: str = "correlator-01",
        auth_lookup: AuthEventLookup | None = None,
    ) -> None:
        self.settings = settings
        self.sensor = SensorIdentity(product="ids-telemetry-engine", sensor_id=sensor_id)
        self.beacon = BeaconDetector(settings.beacon)
        self.dns_tunnel = DnsTunnelDetector(settings.dns_tunnel)
        self.context = TemporalContextIndex(
            max_records_per_endpoint=settings.context_max_records_per_endpoint,
            max_endpoints=settings.context_max_endpoints,
        )
        self.auth_lookup = auth_lookup or NullAuthEventLookup()
        self.auth_lookup_errors = 0

    async def process(self, event: TelemetryEvent) -> tuple[CorrelationAlert, ...]:
        candidate: DetectionCandidate | None = None
        if isinstance(event, SuricataAlert):
            self.context.add_suricata(event)
        elif isinstance(event, EndpointAuthEvent):
            self.context.add_authentication(event)
        elif isinstance(event, ZeekConnection):
            candidate = self.beacon.observe(event)
        elif isinstance(event, ZeekDnsQuery):
            candidate = self.dns_tunnel.observe(event)

        if candidate is None:
            return ()
        return (await self._enrich(candidate),)

    async def _enrich(self, candidate: DetectionCandidate) -> CorrelationAlert:
        endpoints = tuple(
            endpoint for endpoint in (candidate.src_ip, candidate.dst_ip) if endpoint is not None
        )
        context_delta = timedelta(seconds=self.settings.context_window_seconds)
        context_start = candidate.first_seen - context_delta
        context_end = candidate.last_seen + context_delta
        suricata = self.context.find_suricata(
            endpoints=endpoints,
            start=context_start,
            end=context_end,
            limit=self.settings.max_context_matches,
        )

        auth_delta = timedelta(seconds=self.settings.auth_window_seconds)
        auth_start = candidate.first_seen - auth_delta
        auth_end = candidate.last_seen + auth_delta
        local_auth = self.context.find_authentication(
            endpoints=endpoints,
            start=auth_start,
            end=auth_end,
            limit=self.settings.max_context_matches,
        )
        try:
            remote_auth = await self.auth_lookup.search(
                endpoints=endpoints,
                start=auth_start,
                end=auth_end,
                limit=self.settings.max_context_matches,
            )
        except Exception:
            # Detection must remain available when OpenSearch is degraded.
            self.auth_lookup_errors += 1
            remote_auth = ()
            logger.exception(
                "authentication context lookup failed",
                extra={"detection_type": candidate.detection_type.value},
            )
        auth_by_id = {event.event_id: event for event in (*local_auth, *remote_auth)}
        authentication = tuple(
            sorted(auth_by_id.values(), key=lambda event: event.observed_at, reverse=True)
        )[: self.settings.max_context_matches]

        failed_auth_count = sum(event.outcome is AuthOutcome.FAILURE for event in authentication)
        confidence = candidate.confidence
        severity = candidate.severity
        if failed_auth_count:
            confidence += self.settings.auth_failure_confidence_boost
            if self.settings.auth_failure_severity_boost:
                severity = _increase_severity(severity)
        if suricata:
            confidence += 0.05
            if any(event.severity <= 2 for event in suricata):
                severity = _increase_severity(severity)

        evidence = {
            **candidate.evidence,
            "suricata_context_count": len(suricata),
            "authentication_context_count": len(authentication),
            "failed_authentication_count": failed_auth_count,
        }
        description = candidate.description
        if authentication:
            description += (
                f" Correlation found {len(authentication)} endpoint authentication "
                f"event(s), including {failed_auth_count} failure(s), in the time window."
            )
        if suricata:
            description += f" {len(suricata)} related Suricata alert(s) also matched."

        alert_id = stable_event_id(
            "corr",
            candidate.deduplication_key,
            candidate.first_seen.isoformat(),
            candidate.last_seen.isoformat(),
        )
        return CorrelationAlert(
            event_id=alert_id,
            observed_at=candidate.last_seen,
            ingested_at=datetime.now(UTC),
            sensor=self.sensor,
            detection_type=candidate.detection_type,
            title=candidate.title,
            description=description,
            severity=severity,
            confidence=round(min(confidence, 1.0), 4),
            first_seen=candidate.first_seen,
            last_seen=candidate.last_seen,
            src_ip=candidate.src_ip,
            dst_ip=candidate.dst_ip,
            dst_port=candidate.dst_port,
            transport=candidate.transport,
            event_ids=candidate.event_ids,
            evidence=evidence,
            suricata_matches=tuple(
                SuricataEvidence(
                    event_id=event.event_id,
                    signature_id=event.signature_id,
                    signature=event.signature,
                    category=event.category,
                    observed_at=event.observed_at,
                )
                for event in suricata
            ),
            authentication_matches=tuple(
                AuthEvidence(
                    event_id=event.event_id,
                    observed_at=event.observed_at,
                    host_name=event.host_name,
                    principal=event.principal,
                    outcome=event.outcome,
                    action=event.action,
                    provider=event.provider,
                )
                for event in authentication
            ),
            mitre_attack=candidate.mitre_attack,
            nist_controls=NETWORK_MONITORING_CONTROLS,
            tags=(*candidate.tags, "nist-sc-7", "nist-si-4"),
        )


def _increase_severity(severity: AlertSeverity) -> AlertSeverity:
    position = _SEVERITY_ORDER.index(severity)
    return _SEVERITY_ORDER[min(position + 1, len(_SEVERITY_ORDER) - 1)]
