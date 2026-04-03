"""Topology builder — graph from assets and flows."""

from __future__ import annotations

import logging

from luva.analysis.asset_tracker import AssetTracker
from luva.analysis.flow_analyzer import FlowAnalyzer
from luva.models.topology import NetworkTopology, TopologyNode, TopologyEdge

logger = logging.getLogger(__name__)


class TopologyBuilder:
    """Construct NetworkTopology from tracker + flow analyzer."""

    def __init__(self, asset_tracker: AssetTracker, flow_analyzer: FlowAnalyzer):
        self.asset_tracker = asset_tracker
        self.flow_analyzer = flow_analyzer
        self.topology = NetworkTopology()

    def build(self) -> NetworkTopology:
        """Populate nodes, edges, and zones."""
        logger.info("Building network topology graph...")

        self._add_nodes()
        self._add_edges()
        self.topology.detect_zones()

        logger.info(
            "Topology complete: %s nodes, %s edges, %s zones",
            self.topology.graph.number_of_nodes(),
            self.topology.graph.number_of_edges(),
            len(self.topology.zones),
        )

        return self.topology

    def _add_nodes(self) -> None:
        """One TopologyNode per discovered asset."""
        for asset in self.asset_tracker.get_all_assets():
            node = TopologyNode(
                ip_address=asset.ip_address,
                mac_address=asset.mac_address,
                device_role=asset.role,
                vendor=asset.vendor,
                ics_protocols=sorted(asset.protocols_seen),
                risk_score=asset.risk_score,
            )
            self.topology.add_node(node)

    def _add_edges(self) -> None:
        """Edges from aggregated flows."""
        for flow in self.flow_analyzer.get_all_flows():
            edge = TopologyEdge(
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                protocol=flow.ics_protocol or flow.transport_protocol,
                packet_count=flow.packet_count,
                byte_count=flow.byte_count,
                first_seen=flow.start_time.isoformat() if flow.start_time else None,
                last_seen=flow.end_time.isoformat() if flow.end_time else None,
                function_codes_used=sorted(flow.function_codes_seen),
            )
            self.topology.add_edge(edge)

    def export_graphml(self, filepath: str) -> None:
        """Write GraphML to path."""
        self.topology.export_graphml(filepath)
        logger.info("Topology GraphML written to %s", filepath)
