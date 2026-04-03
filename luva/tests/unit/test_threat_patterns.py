"""Threat pattern roll-up from flows and deep_survey."""

from __future__ import annotations

from luva.analysis.threat_patterns import build_threat_pattern_report
from luva.models.asset import Asset, DeviceRole
from luva.models.flow import NetworkFlow


def test_modbus_writes_surface_in_report() -> None:
    fl = NetworkFlow(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=40000,
        dst_port=502,
        transport_protocol="TCP",
        ics_protocol="Modbus",
    )
    fl.modbus_write_fcs_seen.add(6)
    fl.packet_count = 3
    r = build_threat_pattern_report([fl], [], {})
    assert r["summary_counts"]["modbus_write_flows"] == 1
    assert r["modbus_write_flows"][0]["write_function_codes"] == [6]
    assert any("Modbus write" in x["title"] for x in r["executive_findings"])


def test_s7_download_and_stop_flags() -> None:
    fl = NetworkFlow(
        src_ip="10.0.0.5",
        dst_ip="10.0.0.6",
        src_port=50000,
        dst_port=102,
        transport_protocol="TCP",
        ics_protocol="S7",
    )
    fl.s7_service_codes_seen.update({0x1B, 0x29})
    fl.packet_count = 10
    r = build_threat_pattern_report([fl], [], {})
    assert r["summary_counts"]["s7_critical_flows"] == 1


def test_it_remote_and_sequential_hints() -> None:
    flows = []
    for i in range(5):
        f = NetworkFlow(
            src_ip="10.0.0.99",
            dst_ip=f"10.0.1.{i}",
            src_port=40000 + i,
            dst_port=502,
            transport_protocol="TCP",
            ics_protocol="Modbus",
        )
        f.packet_count = 2
        flows.append(f)
    rdp = NetworkFlow(
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        src_port=50123,
        dst_port=3389,
        transport_protocol="TCP",
    )
    rdp.packet_count = 5
    flows.append(rdp)
    r = build_threat_pattern_report(flows, [], {})
    assert r["summary_counts"]["it_remote_protocol_flows"] >= 1
    assert r["summary_counts"]["sequential_ics_sources"] >= 1


def test_modbus_read_non_engineering_hint() -> None:
    fl = NetworkFlow(
        src_ip="10.0.0.77",
        dst_ip="10.0.0.2",
        src_port=45000,
        dst_port=502,
        transport_protocol="TCP",
        ics_protocol="Modbus",
    )
    fl.ics_protocols_seen.add("Modbus")
    fl.function_codes_seen.add(3)
    fl.packet_count = 4
    asset = Asset(ip_address="10.0.0.77", role=DeviceRole.UNKNOWN)
    r = build_threat_pattern_report([fl], [asset], {})
    assert r["summary_counts"]["modbus_read_non_engineering_flows"] >= 1
