"""Aggregate flows into an OT-oriented communication graph (who ↔ whom, which protocol)."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from luva.models.asset import Asset
from luva.models.flow import NetworkFlow


def build_communication_graph(
    flows: list[NetworkFlow],
    assets: list[Asset],
    *,
    max_edges: int = 600,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build nodes + links for visualization and JSON export.

    Each link groups all 5-tuple flows sharing the same (src_ip, dst_ip). ``sessions`` lists
    per-flow application binding: ICS protocol(s), L4 ports, transport, packet/byte counts,
    Modbus/S7-style function codes when present.

    Args:
        flows: All analyzed flows.
        assets: Discovered assets (enrich node role, vendor, risk).
        max_edges: Keep top links by packet count (0 = no limit).

    Returns:
        (graph_dict, meta) where meta notes truncation if applied.
    """
    asset_by_ip = {a.ip_address: a for a in assets}
    pair_rows: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for f in flows:
        protos = sorted(f.ics_protocols_seen) if f.ics_protocols_seen else (
            [p for p in [f.ics_protocol] if p]
        )
        if protos:
            proto_display = ", ".join(protos)
            is_ics = True
        else:
            proto_display = f"{f.transport_protocol}:{f.dst_port}"
            is_ics = False

        pair_rows[(f.src_ip, f.dst_ip)].append(
            {
                "protocols_display": proto_display,
                "ics_protocols": protos,
                "is_ics_traffic": is_ics,
                "transport": f.transport_protocol,
                "l4_src_port": f.src_port,
                "l4_dst_port": f.dst_port,
                "packets": f.packet_count,
                "bytes": f.byte_count,
                "function_codes": sorted(f.function_codes_seen)[:24],
                "has_write_operations": f.has_write_operations,
            },
        )

    link_dicts: list[dict[str, Any]] = []
    for (src_ip, dst_ip), rows in pair_rows.items():
        total_p = sum(r["packets"] for r in rows)
        total_b = sum(r["bytes"] for r in rows)
        ics_labels: set[str] = set()
        for r in rows:
            ics_labels.update(r["ics_protocols"])
        link_dicts.append(
            {
                "source": src_ip,
                "target": dst_ip,
                "total_packets": total_p,
                "total_bytes": total_b,
                "ics_protocols_union": sorted(ics_labels),
                "sessions": rows,
            },
        )

    link_dicts.sort(key=lambda x: x["total_packets"], reverse=True)

    meta: dict[str, Any] = {}
    if max_edges > 0 and len(link_dicts) > max_edges:
        meta["communication_graph_truncated"] = True
        meta["communication_graph_edge_cap"] = max_edges
        meta["communication_graph_total_pairs"] = len(link_dicts)
        link_dicts = link_dicts[:max_edges]

    node_ips: set[str] = set()
    for lk in link_dicts:
        node_ips.add(lk["source"])
        node_ips.add(lk["target"])

    fwd = {(lk["source"], lk["target"]) for lk in link_dicts}
    for lk in link_dicts:
        lk["bidirectional"] = (lk["target"], lk["source"]) in fwd

    nodes: list[dict[str, Any]] = []
    for ip in sorted(node_ips):
        a = asset_by_ip.get(ip)
        nodes.append(
            {
                "id": ip,
                "ip": ip,
                "role": a.role.value if a else "Unknown",
                "vendor": (a.vendor or "") if a else "",
                "mac_address": (a.mac_address or "") if a else "",
                "risk_score": round(a.risk_score, 2) if a else 0.0,
                "protocols_seen": sorted(a.protocols_seen) if a else [],
                "open_ports_sample": sorted(a.open_ports)[:16] if a else [],
            },
        )

    graph = {
        "nodes": nodes,
        "links": link_dicts,
        "description": (
            "Directed communication graph: nodes are IPv4 endpoints; each link aggregates "
            "all 5-tuple flows between the pair. Sessions describe protocol, ports, and volume."
        ),
    }
    return graph, meta
