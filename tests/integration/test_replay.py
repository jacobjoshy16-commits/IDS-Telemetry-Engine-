from __future__ import annotations

import json
from pathlib import Path

import pytest

from ids_telemetry.config import EngineSettings, MetricsSettings, OutputSettings, SourceSettings
from ids_telemetry.daemon import run_daemon


@pytest.mark.integration
@pytest.mark.asyncio
async def test_mixed_sensor_replay_emits_enriched_detections(
    fixture_dir: Path, tmp_path: Path
) -> None:
    output = tmp_path / "alerts.jsonl"
    settings = EngineSettings(
        source=SourceSettings(
            suricata_path=fixture_dir / "suricata_eve.jsonl",
            zeek_conn_path=fixture_dir / "zeek_conn.jsonl",
            zeek_dns_path=fixture_dir / "zeek_dns.jsonl",
            endpoint_auth_path=fixture_dir / "endpoint_auth.jsonl",
            follow=False,
            from_beginning=True,
        ),
        metrics=MetricsSettings(enabled=False),
        output=OutputSettings(jsonl_path=output),
    )

    await run_daemon(settings)

    alerts = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert {alert["detection_type"] for alert in alerts} == {
        "c2_beaconing",
        "dns_tunneling",
    }
    assert all(alert["authentication_matches"] for alert in alerts)
    assert all(alert["suricata_matches"] for alert in alerts)
    assert all(
        {item["control_id"] for item in alert["nist_controls"]} == {"SC-7", "SI-4"}
        for alert in alerts
    )
