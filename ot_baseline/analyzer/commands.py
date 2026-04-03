"""
Modbus/TCP command profile (function codes, read vs write, writers, rare FCs).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from ot_baseline.parser.modbus_tcp import iter_modbus_requests_from_tcp_payload
from ot_baseline.parser.records import PacketRecord


@dataclass
class CommandProfileAnalyzer:
    """Parse Modbus on TCP/502 only (passive segment heuristic)."""

    _fc_counts: Counter[int] = field(default_factory=Counter)
    _fc_by_src: defaultdict[int, Counter] = field(default_factory=lambda: defaultdict(Counter))
    _write_sources: set[str] = field(default_factory=set)
    _read_pkts: int = 0
    _write_pkts: int = 0
    _other_pkts: int = 0

    def consume(self, rec: PacketRecord) -> None:
        if rec.proto != "tcp" or rec.tcp_payload is None:
            return
        if 502 not in {rec.sport, rec.dport}:
            return
        for fc, cat in iter_modbus_requests_from_tcp_payload(rec.tcp_payload):
            self._fc_counts[fc] += 1
            self._fc_by_src[fc][rec.src_ip] += 1
            if cat == "write":
                self._write_pkts += 1
                self._write_sources.add(rec.src_ip)
            elif cat == "read":
                self._read_pkts += 1
            else:
                self._other_pkts += 1

    def to_dict(self, *, rare_fc_ratio: float = 0.002) -> dict[str, Any]:
        total = sum(self._fc_counts.values()) or 1
        threshold = max(1, int(total * rare_fc_ratio))
        by_fc = [
            {
                "function_code": fc,
                "count": n,
                "percent_of_modbus_pdus": round(100.0 * n / total, 4),
                "top_sources": self._fc_by_src[fc].most_common(8),
                "flag_rare": n <= threshold,
            }
            for fc, n in sorted(self._fc_counts.items(), key=lambda x: -x[1])
        ]

        # Uncommon vs dominant set: FCs below 1% of total modbus
        uncommon = [row for row in by_fc if row["percent_of_modbus_pdus"] < 1.0 and row["count"] > 0]

        return {
            "scope": "modbus_tcp_port_502_heuristic",
            "totals": {
                "modbus_pdus_parsed": total,
                "classified_read_like": self._read_pkts,
                "classified_write_like": self._write_pkts,
                "classified_other": self._other_pkts,
            },
            "write_source_ips": sorted(self._write_sources),
            "function_codes": by_fc,
            "flags": {
                "rare_function_codes": [r for r in by_fc if r["flag_rare"]],
                "uncommon_under_one_percent": uncommon,
                "ics_write_activity": len(self._write_sources) > 0,
                "note": "Writes in baseline may be legitimate HMI/SCADA — track changes vs future captures.",
            },
        }
