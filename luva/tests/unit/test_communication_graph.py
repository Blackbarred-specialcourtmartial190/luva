"""Communication graph aggregation for OT map export."""

from __future__ import annotations

from datetime import datetime, timezone

from luva.analysis.communication_graph import build_communication_graph
from luva.models.asset import Asset, DeviceRole
from luva.models.flow import NetworkFlow


def test_build_communication_graph_merges_pair_and_sessions() -> None:
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    f1 = NetworkFlow(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=40000, dst_port=502,
        transport_protocol="TCP", ics_protocol="Modbus",
    )
    f1.packet_count = 10
    f1.byte_count = 100
    f1.start_time = t0
    f1.end_time = t0
    f1.ics_protocols_seen.add("Modbus")

    f2 = NetworkFlow(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=40001, dst_port=102,
        transport_protocol="TCP", ics_protocol="S7",
    )
    f2.packet_count = 3
    f2.byte_count = 200
    f2.start_time = t0
    f2.end_time = t0
    f2.ics_protocols_seen.add("S7")

    assets = [
        Asset(ip_address="10.0.0.1", role=DeviceRole.HMI, vendor="ACME"),
        Asset(ip_address="10.0.0.2", role=DeviceRole.PLC),
    ]

    graph, meta = build_communication_graph([f1, f2], assets, max_edges=100)
    assert not meta.get("communication_graph_truncated")
    assert len(graph["links"]) == 1
    lk = graph["links"][0]
    assert lk["source"] == "10.0.0.1"
    assert lk["target"] == "10.0.0.2"
    assert lk["total_packets"] == 13
    assert set(lk["ics_protocols_union"]) == {"Modbus", "S7"}
    assert len(lk["sessions"]) == 2

    by_ip = {n["id"]: n for n in graph["nodes"]}
    assert by_ip["10.0.0.1"]["vendor"] == "ACME"
    assert by_ip["10.0.0.2"]["role"] == "Programmable Logic Controller"


def test_truncate_respects_max_edges() -> None:
    flows = []
    for i in range(5):
        f = NetworkFlow(
            src_ip=f"10.0.{i}.1", dst_ip=f"10.0.{i}.2",
            src_port=1000 + i, dst_port=502, transport_protocol="TCP",
        )
        f.packet_count = 100 - i
        flows.append(f)
    g, m = build_communication_graph(flows, [], max_edges=2)
    assert m.get("communication_graph_truncated") is True
    assert len(g["links"]) == 2
