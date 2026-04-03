"""
Communication map: who talks to whom, volume, talkers, one-to-many, rare edges.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from ot_baseline.parser.records import PacketRecord


@dataclass
class CommunicationAnalyzer:
    """Accumulate directed edges (src_ip -> dst_ip)."""

    _pkt: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    _bytes: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    _host_bytes: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _src_peers: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def consume(self, rec: PacketRecord) -> None:
        key = (rec.src_ip, rec.dst_ip)
        self._pkt[key] += 1
        self._bytes[key] += rec.length
        self._host_bytes[rec.src_ip] += rec.length
        self._host_bytes[rec.dst_ip] += rec.length
        self._src_peers[rec.src_ip].add(rec.dst_ip)

    def to_dict(self, *, rare_percentile: float = 10.0, one_to_many_min_peers: int = 8) -> dict[str, Any]:
        """Export JSON-serializable communication map and derived patterns."""
        edges: list[dict[str, Any]] = []
        for (src, dst), n in sorted(self._pkt.items(), key=lambda x: -x[1]):
            edges.append(
                {
                    "src_ip": src,
                    "dst_ip": dst,
                    "packets": n,
                    "bytes": self._bytes[(src, dst)],
                },
            )

        # Top talkers by bytes touching host (src+dst accounting above double-counts per flow — SOC view: sort by host total)
        hosts = sorted(self._host_bytes.items(), key=lambda x: -x[1])[:50]
        hosts_out = [{"ip": ip, "total_bytes": b, "distinct_peers_as_src": len(self._src_peers.get(ip, ()))} for ip, b in hosts]

        counts = np.array([self._pkt[k] for k in self._pkt], dtype=np.int64) if self._pkt else np.array([], dtype=np.int64)
        rare_threshold = float(np.percentile(counts, rare_percentile)) if len(counts) else 0.0
        rare_edges = [
            {"src_ip": s, "dst_ip": d, "packets": self._pkt[(s, d)], "bytes": self._bytes[(s, d)]}
            for s, d in self._pkt
            if self._pkt[(s, d)] <= rare_threshold and self._pkt[(s, d)] > 0
        ]
        rare_edges.sort(key=lambda x: x["packets"])

        one_to_many = [
            {"src_ip": src, "distinct_destinations": len(peers), "sample_peers": sorted(peers)[:16]}
            for src, peers in self._src_peers.items()
            if len(peers) >= one_to_many_min_peers
        ]
        one_to_many.sort(key=lambda x: -x["distinct_destinations"])

        return {
            "edges": edges,
            "summary": {
                "unique_edges": len(self._pkt),
                "unique_hosts": len(self._host_bytes),
                "rare_edge_percentile_threshold": rare_threshold,
                "rare_edge_definition": f"packet_count <= p{rare_percentile:g} of all edges",
            },
            "top_hosts_by_volume": hosts_out,
            "patterns": {
                "one_to_many_sources": one_to_many[:40],
                "rare_low_volume_edges": rare_edges[:200],
            },
        }
