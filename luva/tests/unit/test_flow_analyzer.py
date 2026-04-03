"""Unit tests for flow analyzer."""

from __future__ import annotations

from datetime import datetime, timezone

from luva.analysis.flow_analyzer import FlowAnalyzer
from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.base import ProtocolFrame


def _pkt(n: int, src: str, dst: str, sport: int, dport: int) -> PacketMetadata:
    ts = datetime(2026, 1, 1, 12, 0, n, tzinfo=timezone.utc)
    return PacketMetadata(
        packet_number=n,
        timestamp=ts,
        length=100,
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        transport="TCP",
        payload=b"",
        payload_length=0,
    )


def test_flow_key_and_counts() -> None:
    """Same 5-tuple aggregates into one flow."""
    fa = FlowAnalyzer()
    fa.process_packet(_pkt(1, "10.0.0.1", "10.0.0.2", 40000, 502))
    fa.process_packet(_pkt(2, "10.0.0.1", "10.0.0.2", 40000, 502))
    assert fa.flow_count == 1
    flows = fa.get_all_flows()
    assert flows[0].packet_count == 2
    assert flows[0].byte_count == 200


def test_multiple_ics_protocols_on_same_flow() -> None:
    """Same 5-tuple can accumulate several ICS labels (multi-parser pipeline)."""
    fa = FlowAnalyzer()
    fk = fa.process_packet(_pkt(1, "10.0.0.1", "10.0.0.2", 40000, 502))
    assert fk is not None
    ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    fa.process_frame(
        ProtocolFrame(
            timestamp=ts,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=40000,
            dst_port=502,
            protocol="Modbus",
            protocol_slug="modbus",
        ),
        fk,
    )
    fa.process_frame(
        ProtocolFrame(
            timestamp=ts,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=40000,
            dst_port=502,
            protocol="S7",
            protocol_slug="s7",
        ),
        fk,
    )
    flow = fa.get_flow(fk)
    assert flow is not None
    assert flow.ics_protocols_seen == {"Modbus", "S7"}
    assert flow.ics_protocol == "Modbus, S7"
    dist = fa.get_protocol_distribution()
    assert dist.get("Modbus", 0) >= 1
    assert dist.get("S7", 0) >= 1


def test_top_talkers() -> None:
    """Top talkers ranked by packet count."""
    fa = FlowAnalyzer()
    fa.process_packet(_pkt(1, "10.0.0.1", "10.0.0.2", 1, 502))
    fa.process_packet(_pkt(2, "10.0.0.1", "10.0.0.2", 1, 502))
    fa.process_packet(_pkt(3, "10.0.0.3", "10.0.0.2", 2, 502))
    top = fa.get_top_talkers(2)
    assert top[0][0] == "10.0.0.1"
    assert top[0][1] == 2
