from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from ids_telemetry.config import (
    BeaconSettings,
    EngineSettings,
    OpenSearchSettings,
    SourceSettings,
)


def test_source_requires_at_least_one_path() -> None:
    with pytest.raises(ValidationError, match="at least one telemetry source"):
        SourceSettings()


def test_period_configuration_is_consistent() -> None:
    with pytest.raises(ValidationError, match="max_period_seconds"):
        BeaconSettings(min_period_seconds=60, max_period_seconds=30)


def test_opensearch_credentials_are_a_pair() -> None:
    with pytest.raises(ValidationError, match="configured together"):
        OpenSearchSettings(username="analyst")


def test_settings_accept_nested_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDS_SOURCE__SURICATA_PATH", "/logs/eve.json")
    monkeypatch.setenv("IDS_SOURCE__FOLLOW", "false")
    monkeypatch.setenv("IDS_CORRELATION__BEACON__MIN_EVENTS", "10")
    settings = EngineSettings()
    assert settings.source.suricata_path == Path("/logs/eve.json")
    assert settings.source.follow is False
    assert settings.correlation.beacon.min_events == 10
