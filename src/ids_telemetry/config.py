"""Environment-driven runtime configuration with startup validation."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SourceSettings(ConfigModel):
    suricata_path: Path | None = None
    zeek_conn_path: Path | None = None
    zeek_dns_path: Path | None = None
    endpoint_auth_path: Path | None = None
    follow: bool = True
    from_beginning: bool = False
    poll_interval_seconds: float = Field(default=0.2, gt=0.0, le=10.0)

    @model_validator(mode="after")
    def require_source(self) -> SourceSettings:
        if not any(
            (
                self.suricata_path,
                self.zeek_conn_path,
                self.zeek_dns_path,
                self.endpoint_auth_path,
            )
        ):
            raise ValueError("at least one telemetry source path must be configured")
        return self


class BeaconSettings(ConfigModel):
    window_seconds: float = Field(default=900.0, ge=30.0, le=86400.0)
    min_events: int = Field(default=8, ge=4, le=1000)
    min_period_seconds: float = Field(default=5.0, gt=0.0)
    max_period_seconds: float = Field(default=600.0, gt=0.0)
    max_jitter_ratio: float = Field(default=0.35, gt=0.0, le=1.0)
    max_coefficient_variation: float = Field(default=0.45, gt=0.0, le=2.0)
    minimum_score: float = Field(default=0.68, ge=0.0, le=1.0)
    cooldown_seconds: float = Field(default=600.0, ge=0.0, le=86400.0)
    max_keys: int = Field(default=20_000, ge=100)
    max_events_per_key: int = Field(default=256, ge=16, le=100_000)
    max_total_events: int = Field(default=250_000, ge=1_000)

    @model_validator(mode="after")
    def validate_periods(self) -> BeaconSettings:
        if self.max_period_seconds <= self.min_period_seconds:
            raise ValueError("max_period_seconds must exceed min_period_seconds")
        if self.window_seconds < self.min_period_seconds * (self.min_events - 1):
            raise ValueError("beacon window cannot hold the minimum event sequence")
        if self.max_events_per_key < self.min_events:
            raise ValueError("max_events_per_key must be at least min_events")
        if self.max_total_events < self.max_events_per_key:
            raise ValueError("max_total_events must be at least max_events_per_key")
        return self


class DnsTunnelSettings(ConfigModel):
    window_seconds: float = Field(default=300.0, ge=30.0, le=86400.0)
    min_queries: int = Field(default=12, ge=4, le=10000)
    long_query_characters: int = Field(default=45, ge=20, le=253)
    encoded_label_characters: int = Field(default=24, ge=8, le=63)
    entropy_threshold: float = Field(default=3.5, ge=1.0, le=6.0)
    query_rate_per_minute: float = Field(default=4.0, gt=0.0)
    minimum_score: float = Field(default=0.67, ge=0.0, le=1.0)
    cooldown_seconds: float = Field(default=600.0, ge=0.0, le=86400.0)
    allowlisted_domains: tuple[str, ...] = (
        "in-addr.arpa",
        "ip6.arpa",
        "windows.com",
    )
    max_keys: int = Field(default=20_000, ge=100)
    max_events_per_key: int = Field(default=512, ge=16, le=100_000)
    max_total_events: int = Field(default=250_000, ge=1_000)

    @model_validator(mode="after")
    def validate_capacity(self) -> DnsTunnelSettings:
        if self.max_events_per_key < self.min_queries:
            raise ValueError("max_events_per_key must be at least min_queries")
        if self.max_total_events < self.max_events_per_key:
            raise ValueError("max_total_events must be at least max_events_per_key")
        return self


class CorrelationSettings(ConfigModel):
    context_window_seconds: float = Field(default=600.0, ge=1.0, le=86400.0)
    auth_window_seconds: float = Field(default=900.0, ge=1.0, le=86400.0)
    max_context_matches: int = Field(default=20, ge=1, le=500)
    context_max_records_per_endpoint: int = Field(default=256, ge=16, le=10_000)
    context_max_endpoints: int = Field(default=20_000, ge=100, le=1_000_000)
    auth_failure_confidence_boost: float = Field(default=0.10, ge=0.0, le=0.5)
    auth_failure_severity_boost: bool = True
    beacon: BeaconSettings = Field(default_factory=BeaconSettings)
    dns_tunnel: DnsTunnelSettings = Field(default_factory=DnsTunnelSettings)


class OpenSearchSettings(ConfigModel):
    enabled: bool = False
    hosts: tuple[str, ...] = ("http://opensearch:9200",)
    username: str | None = None
    password: SecretStr | None = None
    verify_certs: bool = True
    ca_certs: Path | None = None
    events_index_prefix: str = "ids-telemetry-events"
    alerts_index_prefix: str = "ids-correlation-alerts"
    metrics_index_prefix: str = "ids-engine-metrics"
    auth_index_pattern: str = "logs-endpoint.events.authentication-*"
    dead_letter_path: Path | None = None
    batch_size: int = Field(default=500, ge=1, le=5000)
    flush_interval_seconds: float = Field(default=1.0, gt=0.0, le=60.0)
    request_timeout_seconds: float = Field(default=10.0, gt=0.0, le=120.0)
    max_retries: int = Field(default=3, ge=0, le=10)

    @model_validator(mode="after")
    def require_credentials_pair(self) -> OpenSearchSettings:
        if (self.username is None) != (self.password is None):
            raise ValueError("OpenSearch username and password must be configured together")
        return self


class OutputSettings(ConfigModel):
    jsonl_path: Path | None = None
    include_normalized_events: bool = False
    include_metric_snapshots: bool = True


class MetricsSettings(ConfigModel):
    enabled: bool = True
    bind_host: str = "0.0.0.0"
    port: int = Field(default=9108, ge=1, le=65535)
    snapshot_interval_seconds: float = Field(default=60.0, gt=0.0, le=3600.0)


class EngineSettings(BaseSettings):
    """Top-level settings loaded from ``IDS_*`` environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="IDS_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    service_name: str = "ids-telemetry-engine"
    sensor_id: str = "correlator-01"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    queue_size: int = Field(default=20_000, ge=100, le=1_000_000)
    source: SourceSettings
    correlation: CorrelationSettings = Field(default_factory=CorrelationSettings)
    opensearch: OpenSearchSettings = Field(default_factory=OpenSearchSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    metrics: MetricsSettings = Field(default_factory=MetricsSettings)
