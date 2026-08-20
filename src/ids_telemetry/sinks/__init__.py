"""Telemetry output sinks."""

from ids_telemetry.sinks.base import CompositeSink, EventSink, NullSink
from ids_telemetry.sinks.jsonl import JsonlSink
from ids_telemetry.sinks.opensearch import OpenSearchBulkSink

__all__ = ["CompositeSink", "EventSink", "JsonlSink", "NullSink", "OpenSearchBulkSink"]
