"""TopologyBuilder produces a graph with nodes and edges."""

from __future__ import annotations

from datetime import datetime, timezone

from luva.analysis.asset_tracker import AssetTracker
from luva.analysis.flow_analyzer import FlowAnalyzer
from luva.analysis.topology import TopologyBuilder
from luva.engine.pcap_reader import PacketMetadata


def test_topology_builder_adds_nodes_and_edges() -> None:
    ts = datetime.now(timezone.utc)
    pkt = PacketMetadata(
        packet_number=1,
        timestamp=ts,
        length=80,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=40000,
        dst_port=502,
        transport="TCP",
    )
    tracker = AssetTracker()
    tracker.process_packet(pkt)
    flows = FlowAnalyzer()
    flows.process_packet(pkt)

    topo = TopologyBuilder(tracker, flows).build()
    assert topo.graph.number_of_nodes() >= 2
    assert topo.graph.number_of_edges() >= 1
