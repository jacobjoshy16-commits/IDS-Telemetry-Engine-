"""Sliding-window detector for low-jitter and bounded-jitter C2 beaconing."""

from __future__ import annotations

import statistics
from collections import OrderedDict
from datetime import datetime
from itertools import pairwise

from ids_telemetry.config import BeaconSettings
from ids_telemetry.correlation.types import DetectionCandidate
from ids_telemetry.correlation.window import KeyedSlidingWindow
from ids_telemetry.models import (
    BEACON_TECHNIQUES,
    AlertSeverity,
    DetectionType,
    ZeekConnection,
)

BeaconKey = tuple[str, str, int | None, str]


class BeaconDetector:
    def __init__(self, settings: BeaconSettings) -> None:
        self.settings = settings
        self._windows: KeyedSlidingWindow[BeaconKey, ZeekConnection] = KeyedSlidingWindow(
            window_seconds=settings.window_seconds,
            max_keys=settings.max_keys,
            max_values_per_key=settings.max_events_per_key,
            max_total_values=settings.max_total_events,
        )
        self._last_alert: OrderedDict[BeaconKey, datetime] = OrderedDict()

    def observe(self, event: ZeekConnection) -> DetectionCandidate | None:
        if event.src_ip == event.dst_ip or event.dst_ip.is_multicast or event.dst_ip.is_unspecified:
            return None
        # DNS has a purpose-built detector and periodic resolver traffic is common.
        if event.dst_port == 53:
            return None

        key: BeaconKey = (
            str(event.src_ip),
            str(event.dst_ip),
            event.dst_port,
            event.transport,
        )
        current = self._windows.values(key)
        if any(entry.value.event_id == event.event_id for entry in current):
            return None
        entries = self._windows.add(key, event.observed_at, event)
        if len(entries) < self.settings.min_events:
            return None

        timestamps = [entry.timestamp for entry in entries]
        intervals = [
            (right - left).total_seconds() for left, right in pairwise(timestamps) if right > left
        ]
        if len(intervals) < self.settings.min_events - 1:
            return None

        median_interval = statistics.median(intervals)
        if not (
            self.settings.min_period_seconds <= median_interval <= self.settings.max_period_seconds
        ):
            return None

        mean_interval = statistics.fmean(intervals)
        coefficient_variation = (
            statistics.pstdev(intervals) / mean_interval if mean_interval > 0 else float("inf")
        )
        median_deviation = statistics.median(
            abs(interval - median_interval) for interval in intervals
        )
        jitter_ratio = median_deviation / median_interval
        tolerance = median_interval * self.settings.max_jitter_ratio
        in_band_ratio = sum(
            abs(interval - median_interval) <= tolerance for interval in intervals
        ) / len(intervals)

        jitter_component = max(0.0, 1.0 - jitter_ratio / self.settings.max_jitter_ratio)
        variation_component = max(
            0.0,
            1.0 - coefficient_variation / self.settings.max_coefficient_variation,
        )
        sample_component = min(1.0, len(entries) / (self.settings.min_events * 2.0))
        score = (
            0.40 * jitter_component
            + 0.30 * variation_component
            + 0.20 * in_band_ratio
            + 0.10 * sample_component
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

        payload_sizes = [
            (entry.value.orig_bytes or 0) + (entry.value.resp_bytes or 0) for entry in entries
        ]
        severity = AlertSeverity.HIGH if score >= 0.85 else AlertSeverity.MEDIUM
        return DetectionCandidate(
            detection_type=DetectionType.BEACONING,
            title="Periodic outbound connection pattern consistent with C2 beaconing",
            description=(
                f"{event.src_ip} repeatedly contacted {event.dst_ip}:{event.dst_port} "
                f"at a median interval of {median_interval:.1f} seconds with bounded jitter."
            ),
            severity=severity,
            confidence=round(min(score, 1.0), 4),
            first_seen=timestamps[0],
            last_seen=timestamps[-1],
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            transport=event.transport,
            event_ids=tuple(entry.value.event_id for entry in entries[-64:]),
            evidence={
                "connection_count": len(entries),
                "interval_count": len(intervals),
                "median_interval_seconds": round(median_interval, 4),
                "median_absolute_jitter_ratio": round(jitter_ratio, 6),
                "coefficient_of_variation": round(coefficient_variation, 6),
                "intervals_within_jitter_band_ratio": round(in_band_ratio, 6),
                "mean_payload_bytes": round(statistics.fmean(payload_sizes), 2),
                "detector_score": round(score, 6),
            },
            mitre_attack=BEACON_TECHNIQUES,
            tags=("nsm", "c2", "beaconing", "zeek"),
            deduplication_key="|".join(map(str, (DetectionType.BEACONING.value, *key))),
        )
