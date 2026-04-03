"""Compare a previous analysis JSON snapshot with the current run."""

from __future__ import annotations

from typing import Any


def _asset_ips(report: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for a in report.get("assets") or []:
        ip = a.get("ip_address")
        if isinstance(ip, str) and ip:
            out.add(ip)
    return out


def _flow_protocols(report: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for f in report.get("flows") or []:
        p = f.get("ics_protocol")
        if isinstance(p, str) and p:
            out.add(p)
    return out


def _anomaly_rule_ids(report: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for e in report.get("anomalies") or []:
        rid = e.get("rule_id")
        if isinstance(rid, str) and rid:
            counts[rid] = counts.get(rid, 0) + 1
    return counts


def diff_analysis_reports(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Summarize deltas between two full ``analysis_report.json``-shaped dicts."""
    b_ips, c_ips = _asset_ips(baseline), _asset_ips(current)
    b_proto, c_proto = _flow_protocols(baseline), _flow_protocols(current)
    b_rules, c_rules = _anomaly_rule_ids(baseline), _anomaly_rule_ids(current)

    all_rule_ids = set(b_rules) | set(c_rules)
    rule_deltas: list[dict[str, Any]] = []
    for rid in sorted(all_rule_ids):
        bc, cc = b_rules.get(rid, 0), c_rules.get(rid, 0)
        if bc != cc:
            rule_deltas.append({"rule_id": rid, "baseline_count": bc, "current_count": cc, "delta": cc - bc})

    return {
        "baseline_summary": baseline.get("summary") or {},
        "current_summary": current.get("summary") or {},
        "new_asset_ips": sorted(c_ips - b_ips),
        "removed_asset_ips": sorted(b_ips - c_ips),
        "new_ics_protocols_in_flows": sorted(c_proto - b_proto),
        "removed_ics_protocols_in_flows": sorted(b_proto - c_proto),
        "anomaly_rule_count_deltas": rule_deltas,
    }
