"""
Temporal behavior: inter-arrival samples on heavy flows to infer polling intervals.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from ot_baseline.parser.records import PacketRecord


def _flow_key(rec: PacketRecord) -> tuple[str, str, str, int | None, int | None]:
    return (rec.src_ip, rec.dst_ip, rec.proto, rec.sport, rec.dport)


@dataclass
class TemporalAnalyzer:
    """
    Track last timestamp per flow and inter-arrival deltas (memory-capped).

    Only flows exceeding ``promote_after_packets`` contribute interval statistics.
    """

    promote_after_packets: int = 12
    max_tracked_flows: int = 8000
    max_samples_per_flow: int = 400

    _flow_count: dict[tuple[str, str, str, int | None, int | None], int] = field(
        default_factory=lambda: defaultdict(int),
    )
    _last_ts: dict[tuple[str, str, str, int | None, int | None], float] = field(default_factory=dict)
    _deltas: dict[tuple[str, str, str, int | None, int | None], list[float]] = field(
        default_factory=lambda: defaultdict(list),
    )

    def consume(self, rec: PacketRecord) -> None:
        k = _flow_key(rec)
        self._flow_count[k] += 1
        n = self._flow_count[k]
        if n < self.promote_after_packets:
            self._last_ts[k] = rec.ts
            return
        if len(self._deltas) >= self.max_tracked_flows and k not in self._deltas:
            return
        prev = self._last_ts.get(k)
        self._last_ts[k] = rec.ts
        if prev is not None:
            dt = rec.ts - prev
            if dt > 0 and len(self._deltas[k]) < self.max_samples_per_flow:
                self._deltas[k].append(dt)

    def to_dict(self, *, top_flows: int = 30) -> dict[str, Any]:
        scored: list[tuple[tuple[str, str, str, int | None, int | None], list[float]]] = []
        for k, samples in self._deltas.items():
            if len(samples) < 8:
                continue
            scored.append((k, samples))
        scored.sort(key=lambda x: -len(x[1]))

        intervals_out: list[dict[str, Any]] = []
        for k, samples in scored[:top_flows]:
            src, dst, proto, sport, dport = k
            arr = np.array(samples, dtype=np.float64)
            med = float(np.median(arr))
            cv = float(np.std(arr) / (med + 1e-9))
            periodic = cv < 0.25 and med >= 0.05
            intervals_out.append(
                {
                    "src_ip": src,
                    "dst_ip": dst,
                    "l4": proto,
                    "src_port": sport,
                    "dst_port": dport,
                    "samples": len(samples),
                    "median_interval_sec": round(med, 6),
                    "interval_cv": round(cv, 4),
                    "likely_periodic_polling": periodic,
                },
            )

        return {
            "flow_timing_top": intervals_out,
            "method": "inter-arrival median/CV on flows with >=8 samples after warmup",
            "limits": {
                "max_tracked_flows": self.max_tracked_flows,
                "max_samples_per_flow": self.max_samples_per_flow,
            },
        }
