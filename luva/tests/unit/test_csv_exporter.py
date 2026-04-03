"""Unit tests for CSV exporter edge cases."""

from __future__ import annotations

from pathlib import Path

from luva.core.pipeline import AnalysisResult
from luva.models.topology import NetworkTopology
from luva.output.csv_exporter import CSVExporter


def test_empty_result_writes_headers(tmp_path: Path) -> None:
    """Empty assets/flows still produce valid CSV with headers."""
    result = AnalysisResult(
        metadata={},
        assets=[],
        flows=[],
        topology=NetworkTopology(),
        anomalies=[],
        statistics={},
    )
    paths = CSVExporter().write(result, tmp_path)
    assert len(paths) == 5
    assets_csv = (tmp_path / "assets.csv").read_text(encoding="utf-8")
    ot_csv = (tmp_path / "ot_assets.csv").read_text(encoding="utf-8")
    flows_csv = (tmp_path / "flows.csv").read_text(encoding="utf-8")
    audit_csv = (tmp_path / "audit_findings.csv").read_text(encoding="utf-8")
    assert "ip_address" in assets_csv
    assert "ot_signals_summary" in ot_csv
    assert "flow_id" in flows_csv
    assert "finding_id" in audit_csv and "mitre_attack_ids" in audit_csv
