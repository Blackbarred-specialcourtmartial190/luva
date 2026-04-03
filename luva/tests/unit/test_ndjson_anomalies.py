"""NDJSON anomaly export."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from luva.core.config import AnalysisConfig, AnomalyCategory, Severity
from luva.core.pipeline import AnalysisResult
from luva.models.asset import Asset
from luva.models.event import AnomalyEvent
from luva.models.topology import NetworkTopology
from luva.output.ndjson_anomalies import NdjsonAnomaliesReporter


def test_ndjson_writes_one_line_per_event(tmp_path: Path) -> None:
    ev = AnomalyEvent(
        severity=Severity.HIGH,
        category=AnomalyCategory.PROTOCOL,
        rule_id="R1",
        rule_name="Test",
        description="d",
        timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        evidence={"src_ip": "192.168.1.1"},
    )
    result = AnalysisResult(
        metadata={"tool": "luva", "version": "t"},
        assets=[Asset(ip_address="192.168.1.1")],
        flows=[],
        topology=NetworkTopology(),
        anomalies=[ev],
        statistics={},
    )
    path = NdjsonAnomaliesReporter().write(result, tmp_path, export_config=None)
    text = path.read_text(encoding="utf-8").strip()
    assert text.count("\n") == 0
    assert "192.168.1.1" in text
    assert "HIGH" in text


def test_ndjson_anonymize_ips(tmp_path: Path) -> None:
    ev = AnomalyEvent(
        severity=Severity.INFO,
        category=AnomalyCategory.NETWORK,
        rule_id="R2",
        rule_name="N",
        description="x",
        evidence={"src_ip": "8.8.8.8"},
    )
    result = AnalysisResult(
        metadata={"tool": "luva", "version": "t"},
        assets=[],
        flows=[],
        topology=NetworkTopology(),
        anomalies=[ev],
        statistics={},
    )
    cfg = AnalysisConfig(anonymize_ips=True)
    path = NdjsonAnomaliesReporter().write(result, tmp_path, export_config=cfg)
    body = path.read_text(encoding="utf-8")
    assert "8.8.8.8" not in body
    assert "10." in body
