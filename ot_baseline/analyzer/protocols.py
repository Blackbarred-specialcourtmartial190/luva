"""
L4 protocol split and ICS-oriented port heuristics (Modbus, S7, DNP3).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from ot_baseline.parser.records import PacketRecord

# Well-known OT server ports (either direction flagged if sport or dport matches)
ICS_TCP_PORTS: dict[int, str] = {
    502: "modbus_tcp",
    102: "s7comm",
    20000: "dnp3_tcp",
}

# Often unwelcome or worth flagging on OT segments (heuristic)
IT_FLAG_PORTS: dict[int, str] = {
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    135: "msrpc",
    139: "netbios_ssn",
    443: "https",
    445: "smb",
    3389: "rdp",
    5900: "vnc",
    5985: "winrm_http",
    5986: "winrm_https",
}


@dataclass
class ProtocolAnalyzer:
    """Count TCP/UDP/ICMP and ICS-labeled flows (by port)."""

    _l4: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _l4_bytes: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _ics_hits: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _ics_bytes: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _it_flag: list[dict[str, Any]] = field(default_factory=list)
    _total_pkts: int = 0
    _pkts_with_any_ics_tcp: int = 0

    def consume(self, rec: PacketRecord) -> None:
        self._total_pkts += 1
        p = rec.proto
        self._l4[p] += 1
        self._l4_bytes[p] += rec.length

        if rec.proto != "tcp":
            return
        ports = {x for x in (rec.sport, rec.dport) if x is not None}
        ics_slugs = {ICS_TCP_PORTS[port] for port in ports if port in ICS_TCP_PORTS}
        if ics_slugs:
            self._pkts_with_any_ics_tcp += 1
            share = rec.length // len(ics_slugs)
            for slug in ics_slugs:
                self._ics_hits[slug] += 1
                self._ics_bytes[slug] += share
        for port in ports:
            if port in IT_FLAG_PORTS:
                self._it_flag.append(
                    {
                        "note": "it_style_port_on_tcp",
                        "port": port,
                        "service_hint": IT_FLAG_PORTS[port],
                        "src_ip": rec.src_ip,
                        "dst_ip": rec.dst_ip,
                    },
                )

    def to_dict(self) -> dict[str, Any]:
        total = max(self._total_pkts, 1)
        l4_rows = []
        for name in sorted(self._l4.keys()):
            n = self._l4[name]
            l4_rows.append(
                {
                    "family": name,
                    "packets": n,
                    "bytes": self._l4_bytes[name],
                    "packet_percent": round(100.0 * n / total, 4),
                },
            )

        non_ics = max(self._total_pkts - self._pkts_with_any_ics_tcp, 0)

        # Deduplicate IT flags (cap list)
        it_unique: dict[tuple[str, str, int], dict[str, Any]] = {}
        for row in self._it_flag:
            k = (row["src_ip"], row["dst_ip"], row["port"])
            it_unique[k] = row
        it_list = list(it_unique.values())[:500]

        return {
            "layer4_distribution": l4_rows,
            "totals": {
                "packets": self._total_pkts,
                "ics_labeled_packets": self._pkts_with_any_ics_tcp,
                "non_ics_labeled_packets": non_ics,
                "ics_packet_ratio": round(self._pkts_with_any_ics_tcp / total, 6) if total else 0.0,
            },
            "ics_by_protocol": [
                {
                    "slug": slug,
                    "packets": self._ics_hits[slug],
                    "bytes": self._ics_bytes[slug],
                }
                for slug in sorted(self._ics_hits.keys())
            ],
            "anomaly_hints": {
                "it_style_tcp_sessions_sample": it_list,
                "note": "IT-flag ports are suspicious on isolated OT VLANs; confirm architecture before alerting.",
            },
        }
