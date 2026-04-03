"""Tests for structured audit workbook."""

from __future__ import annotations

from luva.analysis.audit_workbook import build_audit_workbook
from luva.analysis.pentest_insights import build_pentest_insights
from luva.models.flow import NetworkFlow


def test_workbook_emits_write_surface_finding() -> None:
    fl = NetworkFlow(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=12345,
        dst_port=502,
        transport_protocol="TCP",
        ics_protocol="Modbus",
        has_write_operations=True,
        packet_count=5,
    )
    pent = build_pentest_insights([fl], [], [], {})
    wb = build_audit_workbook([fl], [], [], {}, pent)
    cats = {f["category"] for f in wb["findings"]}
    assert "WRITE_SURFACE" in cats
    assert wb["write_flow_samples"] and wb["write_flow_samples"][0]["src_ip"] == "10.0.0.1"
    assert "scope_statement" in wb and "limitations" in wb
