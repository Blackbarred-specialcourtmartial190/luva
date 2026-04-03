"""JSON and HTML reporters write expected artifacts."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from luva.core.config import AnalysisConfig
from luva.core.pipeline import AnalysisResult
from luva.models.asset import Asset
from luva.models.topology import NetworkTopology
from luva.output.html_reporter import HTMLReporter
from luva.output.json_reporter import JSONReporter
from luva.output.vendor_scripts import read_embedded_script


def _empty_result() -> AnalysisResult:
    return AnalysisResult(
        metadata={"tool": "luva", "version": "test", "analysis_timestamp": datetime.now(timezone.utc).isoformat()},
        assets=[Asset(ip_address="192.168.0.1")],
        flows=[],
        topology=NetworkTopology(),
        anomalies=[],
        statistics={"asset_stats": {}, "flow_stats": {}},
    )


def test_json_reporter_writes_file(tmp_path: Path) -> None:
    out = JSONReporter().write(_empty_result(), tmp_path)
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "192.168.0.1" in text
    assert "assets_discovered" in text


def test_html_reporter_writes_file(tmp_path: Path) -> None:
    out = HTMLReporter().write(_empty_result(), tmp_path, filename="r.html")
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in text.lower() or "<html" in text.lower()
    if read_embedded_script("chart.umd.v4.min.js"):
        assert "cdn.jsdelivr.net/npm/chart.js" not in text
    else:
        assert "cdn.jsdelivr.net/npm/chart.js" in text


def test_json_reporter_respects_privacy_flags(tmp_path: Path) -> None:
    cfg = AnalysisConfig(anonymize_ips=True)
    result = _empty_result()
    path = JSONReporter().write(result, tmp_path, export_config=cfg)
    body = path.read_text(encoding="utf-8")
    assert "192.168.0.1" not in body
    assert "10." in body
