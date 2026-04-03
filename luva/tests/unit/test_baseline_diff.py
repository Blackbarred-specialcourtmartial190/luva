"""Baseline report comparison."""

from __future__ import annotations

from luva.analysis.baseline_diff import diff_analysis_reports


def test_diff_finds_new_and_removed_assets() -> None:
    base = {
        "summary": {"assets_discovered": 1},
        "assets": [{"ip_address": "10.0.0.1"}],
        "flows": [{"ics_protocol": "Modbus"}],
        "anomalies": [{"rule_id": "R1"}],
    }
    cur = {
        "summary": {"assets_discovered": 2},
        "assets": [{"ip_address": "10.0.0.1"}, {"ip_address": "10.0.0.99"}],
        "flows": [{"ics_protocol": "Modbus"}, {"ics_protocol": "S7"}],
        "anomalies": [{"rule_id": "R1"}, {"rule_id": "R1"}],
    }
    d = diff_analysis_reports(base, cur)
    assert "10.0.0.99" in d["new_asset_ips"]
    assert d["removed_asset_ips"] == []
    assert "S7" in d["new_ics_protocols_in_flows"]
    assert any(x["rule_id"] == "R1" and x["delta"] == 1 for x in d["anomaly_rule_count_deltas"])
