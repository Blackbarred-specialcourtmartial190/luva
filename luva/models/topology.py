"""Topology model — NetworkX-backed graph for assets and flows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import networkx as nx

from luva.models.asset import DeviceRole


@dataclass
class TopologyNode:
    """One node in the logical topology graph."""
    ip_address: str
    mac_address: Optional[str] = None
    device_role: DeviceRole = DeviceRole.UNKNOWN
    vendor: Optional[str] = None
    ics_protocols: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    zone: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "device_role": self.device_role.value,
            "vendor": self.vendor,
            "ics_protocols": self.ics_protocols,
            "risk_score": round(self.risk_score, 2),
            "zone": self.zone,
        }


@dataclass
class TopologyEdge:
    """Directed communication summary between two IPs."""
    src_ip: str
    dst_ip: str
    protocol: str  # ICS name or transport label
    packet_count: int = 0
    byte_count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    bidirectional: bool = False
    function_codes_used: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "bidirectional": self.bidirectional,
            "function_codes_used": self.function_codes_used,
        }


@dataclass
class NetworkZone:
    """Heuristic segment (e.g. /24 bucket) for grouping nodes."""
    zone_id: str
    name: str
    subnet: Optional[str] = None
    member_ips: list[str] = field(default_factory=list)
    primary_protocol: Optional[str] = None
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "zone_id": self.zone_id,
            "name": self.name,
            "subnet": self.subnet,
            "member_ips": self.member_ips,
            "primary_protocol": self.primary_protocol,
            "description": self.description,
        }


class NetworkTopology:
    """NetworkX DiGraph plus zone list and export helpers."""

    def __init__(self):
        self.graph: nx.DiGraph = nx.DiGraph()
        self.zones: list[NetworkZone] = []
        self._nodes: dict[str, TopologyNode] = {}
        self._edges: list[TopologyEdge] = []

    def add_node(self, node: TopologyNode) -> None:
        """Insert or refresh a node."""
        self._nodes[node.ip_address] = node
        self.graph.add_node(
            node.ip_address,
            mac_address=node.mac_address,
            device_role=node.device_role.value,
            vendor=node.vendor,
            ics_protocols=node.ics_protocols,
            risk_score=node.risk_score,
            zone=node.zone,
        )

    def add_edge(self, edge: TopologyEdge) -> None:
        """Insert edge or merge counts into an existing parallel edge."""
        self._edges.append(edge)
        if self.graph.has_edge(edge.src_ip, edge.dst_ip):
            # Merge into existing edge
            data = self.graph[edge.src_ip][edge.dst_ip]
            data["packet_count"] = data.get("packet_count", 0) + edge.packet_count
            data["byte_count"] = data.get("byte_count", 0) + edge.byte_count
            protos = set(data.get("protocols", []))
            protos.add(edge.protocol)
            data["protocols"] = list(protos)
        else:
            self.graph.add_edge(
                edge.src_ip,
                edge.dst_ip,
                protocol=edge.protocol,
                packet_count=edge.packet_count,
                byte_count=edge.byte_count,
                first_seen=edge.first_seen,
                last_seen=edge.last_seen,
                protocols=[edge.protocol],
            )

    def detect_zones(self) -> list[NetworkZone]:
        """Group nodes by /24-style IPv4 bucket (best-effort)."""
        from ipaddress import IPv4Address, IPv4Network
        from collections import defaultdict

        subnet_groups: dict[str, list[str]] = defaultdict(list)

        for ip in self.graph.nodes:
            try:
                IPv4Address(ip)
                network = IPv4Network(f"{ip}/24", strict=False)
                subnet_groups[str(network)].append(ip)
            except ValueError:
                subnet_groups["unknown"].append(ip)

        zones = []
        for idx, (subnet, members) in enumerate(sorted(subnet_groups.items())):
            # Dominant ICS protocol in zone
            proto_counts: dict[str, int] = defaultdict(int)
            for member_ip in members:
                node = self._nodes.get(member_ip)
                if node:
                    for proto in node.ics_protocols:
                        proto_counts[proto] += 1

            primary_proto = max(proto_counts, key=lambda k: proto_counts[k]) if proto_counts else None

            zone = NetworkZone(
                zone_id=f"ZONE-{idx + 1:03d}",
                name=f"Segment {subnet}",
                subnet=subnet if subnet != "unknown" else None,
                member_ips=sorted(members),
                primary_protocol=primary_proto,
                description=f"{len(members)} nodes, subnet: {subnet}",
            )
            zones.append(zone)

        self.zones = zones
        return zones

    def get_critical_paths(self) -> list[list[str]]:
        """Shortest paths between high-risk nodes (risk_score >= 7)."""
        critical_nodes = [
            ip for ip, node in self._nodes.items()
            if node.risk_score >= 7.0
        ]

        paths = []
        for i, src in enumerate(critical_nodes):
            for dst in critical_nodes[i + 1:]:
                try:
                    path = nx.shortest_path(self.graph, src, dst)
                    paths.append(path)
                except nx.NetworkXNoPath:
                    pass

        return paths

    def export_graphml(self, filepath: str) -> None:
        """Export topology as GraphML (only types supported by NetworkX GraphML writer)."""

        def _scalar(v: object) -> str | int | float:
            if v is None:
                return ""
            if isinstance(v, bool):
                return int(v)
            if isinstance(v, (int, float)):
                return v
            if isinstance(v, (list, set, tuple)):
                return ",".join(str(x) for x in v)
            if isinstance(v, dict):
                return str(v)
            return str(v)

        g = self.graph.copy()
        for _, data in g.nodes(data=True):
            for k, v in list(data.items()):
                data[k] = _scalar(v)
        for _, _, data in g.edges(data=True):
            for k, v in list(data.items()):
                data[k] = _scalar(v)
        nx.write_graphml(g, filepath)

    def to_dict(self) -> dict:
        """JSON-oriented summary."""
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
            "zones": [z.to_dict() for z in self.zones],
            "critical_paths": self.get_critical_paths(),
            "graph_stats": {
                "total_nodes": self.graph.number_of_nodes(),
                "total_edges": self.graph.number_of_edges(),
                "density": round(nx.density(self.graph), 4) if self.graph.number_of_nodes() > 0 else 0,
                "is_connected": nx.is_weakly_connected(self.graph) if self.graph.number_of_nodes() > 0 else False,
            },
        }
