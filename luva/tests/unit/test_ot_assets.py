"""Unit tests for OT asset classification and export."""

from __future__ import annotations

from luva.analysis.ot_assets import (
    build_ot_assets_export,
    collect_ot_signals,
    is_ot_asset,
)
from luva.models.asset import Asset, DeviceRole


def test_collect_ot_signals_ics_protocol() -> None:
    a = Asset(ip_address="10.0.0.1", protocols_seen={"Modbus", "TCP"})
    sigs = collect_ot_signals(a)
    assert "ics_protocol:Modbus" in sigs


def test_collect_ot_signals_ics_port() -> None:
    a = Asset(ip_address="10.0.0.2", open_ports={502, 443})
    sigs = collect_ot_signals(a)
    assert any(s.startswith("ics_port:502:") for s in sigs)


def test_collect_ot_signals_inferred_role() -> None:
    a = Asset(ip_address="10.0.0.3", role=DeviceRole.PLC)
    sigs = collect_ot_signals(a)
    assert "inferred_role:PLC" in sigs


def test_collect_ot_signals_field_hints() -> None:
    a = Asset(ip_address="10.0.0.4", modbus_unit_ids={1})
    assert "field_hint:modbus_unit_ids" in collect_ot_signals(a)
    b = Asset(ip_address="10.0.0.5", plc_rack=0, plc_slot=2)
    assert "field_hint:s7_rack_slot" in collect_ot_signals(b)
    c = Asset(ip_address="10.0.0.6", dnp3_address=10)
    assert "field_hint:dnp3_address" in collect_ot_signals(c)


def test_is_ot_asset_plain_host_not_ot() -> None:
    a = Asset(ip_address="10.0.0.7", protocols_seen={"TCP"}, open_ports={443})
    assert not is_ot_asset(a)


def test_build_ot_assets_export_sorted_and_fields() -> None:
    assets = [
        Asset(ip_address="10.0.0.10", protocols_seen={"Modbus"}),
        Asset(ip_address="10.0.0.2", open_ports={502}),
        Asset(ip_address="10.0.0.7", protocols_seen={"TCP"}),
    ]
    rows = build_ot_assets_export(assets)
    assert len(rows) == 2
    assert [r["ip_address"] for r in rows] == ["10.0.0.2", "10.0.0.10"]
    assert "ot_signals" in rows[0] and "ot_signals_summary" in rows[0]
    assert "eks_components" in rows[0]
