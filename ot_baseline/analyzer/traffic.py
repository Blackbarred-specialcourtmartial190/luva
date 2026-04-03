"""
Per-second traffic profile: PPS, BPS, mean/peak, spikes/drops vs rolling average.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from ot_baseline.parser.records import PacketRecord


@dataclass
class TrafficAnalyzer:
    """1-second buckets (wall-clock from first seen second in capture)."""

    _sec_pkt: dict[int, int] = field(default_factory=lambda: defaultdict(int))
    _sec_bytes: dict[int, int] = field(default_factory=lambda: defaultdict(int))
    _t0: float | None = None

    def consume(self, rec: PacketRecord) -> None:
        if self._t0 is None:
            self._t0 = rec.ts
        # Relative second index from first observed packet (works with epoch timestamps)
        sec = int(rec.ts - self._t0)
        self._sec_pkt[sec] += 1
        self._sec_bytes[sec] += rec.length

    def to_dict(self, *, spike_factor: float = 3.0, drop_factor: float = 0.1, rolling_window: int = 30) -> dict[str, Any]:
        if not self._sec_pkt:
            return {
                "per_second": [],
                "aggregate": {},
                "anomalies": {"spikes": [], "drops": []},
                "polling_hint": {"note": "no packets"},
            }

        keys = sorted(self._sec_pkt.keys())
        series_pps = np.array([self._sec_pkt[k] for k in keys], dtype=np.float64)
        series_bps = np.array([self._sec_bytes[k] * 8 for k in keys], dtype=np.float64)  # bits per second

        per_second = [
            {
                "t_offset_sec": int(k),
                "packets_per_second": int(self._sec_pkt[k]),
                "bytes_per_second": int(self._sec_bytes[k]),
                "bits_per_second": int(self._sec_bytes[k] * 8),
            }
            for k in keys
        ]

        mean_pps = float(np.mean(series_pps))
        peak_pps = float(np.max(series_pps))
        mean_bps = float(np.mean(series_bps))
        peak_bps = float(np.max(series_bps))

        # Rolling mean (simple) for spike/drop
        spikes: list[dict[str, Any]] = []
        drops: list[dict[str, Any]] = []
        w = max(rolling_window, 1)
        for i, k in enumerate(keys):
            lo = max(0, i - w + 1)
            window = series_pps[lo : i + 1]
            roll = float(np.mean(window))
            pps = series_pps[i]
            if roll >= 5.0 and pps >= spike_factor * roll:
                spikes.append({"t_offset_sec": int(k), "pps": int(pps), "rolling_mean_pps": round(roll, 2)})
            if roll >= 10.0 and pps <= drop_factor * roll:
                drops.append({"t_offset_sec": int(k), "pps": int(pps), "rolling_mean_pps": round(roll, 2)})

        # Simple polling hint: CV of per-second packet counts on active seconds
        active = series_pps[series_pps > 0]
        polling_note = "high variance between active seconds — mixed/burst traffic"
        cv_val: float | None = None
        if len(active) > 5:
            cv_val = float(np.std(active) / (np.mean(active) + 1e-9))
            if cv_val < 0.35:
                polling_note = "relatively stable per-second packet counts — possible steady polling/scan"

        return {
            "per_second": per_second,
            "aggregate": {
                "duration_seconds_observed": int(keys[-1] - keys[0] + 1) if keys else 0,
                "mean_packets_per_second": round(mean_pps, 4),
                "peak_packets_per_second": int(peak_pps),
                "mean_bytes_per_second": round(float(np.mean([self._sec_bytes[k] for k in keys])), 4),
                "peak_bytes_per_second": int(max(self._sec_bytes[k] for k in keys)),
                "mean_bits_per_second": round(mean_bps, 2),
                "peak_bits_per_second": round(peak_bps, 2),
            },
            "anomalies": {
                "spike_threshold": f"pps >= {spike_factor}x {rolling_window}s rolling mean (min baseline 5 pps)",
                "spikes": spikes[:200],
                "drop_threshold": f"pps <= {drop_factor}x rolling mean (min baseline 10 pps)",
                "drops": drops[:200],
            },
            "polling_hint": {
                "note": polling_note,
                "active_second_packet_cv": round(cv_val, 4) if cv_val is not None else None,
            },
        }
