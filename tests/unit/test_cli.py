from __future__ import annotations

import json
from pathlib import Path

import pytest

from ids_telemetry import cli
from ids_telemetry.config import EngineSettings


def test_validate_command_reports_valid_file(
    fixture_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    result = cli.main(["validate", "suricata", str(fixture_dir / "suricata_eve.jsonl")])
    summary = json.loads(capsys.readouterr().out)
    assert result == 0
    assert summary["valid"] == 2
    assert summary["invalid"] == 0


def test_validate_command_reports_bad_lines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text("\n{bad json\n", encoding="utf-8")
    result = cli.main(["validate", "zeek-dns", str(path)])
    captured = capsys.readouterr()
    assert result == 1
    assert json.loads(captured.out)["invalid"] == 1
    assert json.loads(captured.err)["line"] == 2


def test_validate_command_handles_missing_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    result = cli.main(["validate", "endpoint-auth", str(tmp_path / "missing")])
    assert result == 2
    assert "cannot read" in capsys.readouterr().err


def test_schema_command_prints_alert_schema(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["schema", "alert"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert schema["properties"]["detection_type"]
    assert schema["additionalProperties"] is False


def test_replay_command_runs_end_to_end(
    fixture_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "alerts.jsonl"
    output.write_text("stale\n", encoding="utf-8")
    result = cli.main(
        [
            "replay",
            "--suricata",
            str(fixture_dir / "suricata_eve.jsonl"),
            "--zeek-conn",
            str(fixture_dir / "zeek_conn.jsonl"),
            "--zeek-dns",
            str(fixture_dir / "zeek_dns.jsonl"),
            "--endpoint-auth",
            str(fixture_dir / "endpoint_auth.jsonl"),
            "--include-events",
            "--output",
            str(output),
        ]
    )
    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert result == 0
    assert "stale" not in output.read_text(encoding="utf-8")
    assert len(records) == 32
    assert sum(record["kind"] == "correlation.alert" for record in records) == 2
    assert capsys.readouterr().err == ""


def test_configuration_error_without_source(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for key in tuple(__import__("os").environ):
        if key.startswith("IDS_SOURCE__"):
            monkeypatch.delenv(key)
    assert cli.main(["replay"]) == 2
    assert "configuration error" in capsys.readouterr().err


@pytest.mark.parametrize(
    "raised, expected", [(KeyboardInterrupt(), 130), (RuntimeError("boom"), 1)]
)
def test_daemon_exit_codes(
    raised: BaseException,
    expected: int,
    fixture_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def fail(_settings: EngineSettings, **_: object) -> None:
        raise raised

    monkeypatch.setattr(cli, "run_daemon", fail)
    result = cli.main(["run", "--suricata", str(fixture_dir / "suricata_eve.jsonl")])
    assert result == expected
    if expected == 1:
        assert "fatal: boom" in capsys.readouterr().err


def test_command_settings_enable_requested_opensearch(
    fixture_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[EngineSettings] = []

    async def capture(settings: EngineSettings, **_: object) -> None:
        captured.append(settings)

    monkeypatch.setattr(cli, "run_daemon", capture)
    result = cli.main(
        [
            "replay",
            "--suricata",
            str(fixture_dir / "suricata_eve.jsonl"),
            "--opensearch",
            "--log-level",
            "DEBUG",
        ]
    )
    assert result == 0
    assert captured[0].opensearch.enabled is True
    assert captured[0].log_level == "DEBUG"
