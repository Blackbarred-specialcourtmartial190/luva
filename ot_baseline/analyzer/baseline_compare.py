"""
Optional diff against a prior baseline export directory (JSON artifacts).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _load_json(p: Path) -> dict[str, Any] | None:
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Could not load %s: %s", p, exc)
        return None


def _edge_set(comm: dict[str, Any]) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for e in comm.get("edges") or []:
        out.add((str(e.get("src_ip")), str(e.get("dst_ip"))))
    return out


def _host_set(comm: dict[str, Any]) -> set[str]:
    hosts: set[str] = set()
    for e in comm.get("edges") or []:
        hosts.add(str(e.get("src_ip")))
        hosts.add(str(e.get("dst_ip")))
    for h in comm.get("top_hosts_by_volume") or []:
        hosts.add(str(h.get("ip")))
    return hosts


class BaselineComparator:
    """Compare current run artifacts to a previous ``baseline_dir``."""

    def __init__(self, baseline_dir: Path | None) -> None:
        self.baseline_dir = Path(baseline_dir) if baseline_dir else None
        self._prev_comm: dict[str, Any] | None = None
        self._prev_traffic: dict[str, Any] | None = None
        self._prev_cmd: dict[str, Any] | None = None
        if self.baseline_dir and self.baseline_dir.is_dir():
            self._prev_comm = _load_json(self.baseline_dir / "communication_map.json")
            self._prev_traffic = _load_json(self.baseline_dir / "traffic_profile.json")
            self._prev_cmd = _load_json(self.baseline_dir / "command_profile.json")
        elif self.baseline_dir:
            logger.warning("Baseline directory does not exist: %s", self.baseline_dir)

    def diff(
        self,
        comm: dict[str, Any],
        traffic: dict[str, Any],
        cmd: dict[str, Any],
        *,
        traffic_ratio_alert: float = 2.0,
    ) -> dict[str, Any]:
        """Produce SOC-oriented flags comparing current vs stored baseline."""
        if not self._prev_comm:
            return {
                "baseline_loaded": False,
                "note": "No prior communication_map.json in baseline directory — run saved as baseline only.",
            }

        cur_hosts = _host_set(comm)
        base_hosts = _host_set(self._prev_comm)
        new_devices = sorted(cur_hosts - base_hosts)

        cur_e = _edge_set(comm)
        base_e = _edge_set(self._prev_comm)
        new_edges = sorted(cur_e - base_e)

        traffic_alert = False
        detail_traffic = {}
        if self._prev_traffic:
            prev_mean = (self._prev_traffic.get("aggregate") or {}).get("mean_packets_per_second")
            cur_mean = (traffic.get("aggregate") or {}).get("mean_packets_per_second")
            if isinstance(prev_mean, (int, float)) and isinstance(cur_mean, (int, float)) and prev_mean > 0.5:
                ratio = float(cur_mean) / float(prev_mean)
                detail_traffic = {"mean_pps_ratio_vs_baseline": round(ratio, 4)}
                if ratio >= traffic_ratio_alert:
                    traffic_alert = True

        write_alert = False
        detail_cmd: dict[str, Any] = {}
        if self._prev_cmd and cmd:
            prev_w = len((self._prev_cmd.get("write_source_ips") or []))
            cur_w = len((cmd.get("write_source_ips") or []))
            prev_writes = (self._prev_cmd.get("totals") or {}).get("classified_write_like", 0)
            cur_writes = (cmd.get("totals") or {}).get("classified_write_like", 0)
            detail_cmd = {
                "baseline_write_sources": prev_w,
                "current_write_sources": cur_w,
                "baseline_write_pdus": prev_writes,
                "current_write_pdus": cur_writes,
            }
            if cur_writes > max(prev_writes, 0) * 2 and cur_writes > 5:
                write_alert = True
            new_writers = sorted(set(cmd.get("write_source_ips") or []) - set(self._prev_cmd.get("write_source_ips") or []))
            detail_cmd["new_write_source_ips"] = new_writers
            if new_writers:
                write_alert = True

        return {
            "baseline_loaded": True,
            "baseline_dir": str(self.baseline_dir) if self.baseline_dir else None,
            "new_devices": new_devices,
            "new_communication_pairs": [{"src_ip": a, "dst_ip": b} for a, b in new_edges[:500]],
            "new_communication_pairs_truncated": max(0, len(new_edges) - 500),
            "traffic": {**detail_traffic, "anomalous_traffic_increase": traffic_alert},
            "modbus_writes": {**detail_cmd, "ics_write_activity_flag": write_alert},
        }
