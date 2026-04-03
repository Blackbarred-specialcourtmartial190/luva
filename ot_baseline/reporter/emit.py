"""
Write structured JSON reports and a human-readable summary.txt.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def write_json(path: Path, payload: dict[str, Any]) -> Path:
    """Atomic-friendly write: serialize to UTF-8 JSON with stable indentation."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    path.write_text(text + "\n", encoding="utf-8")
    logger.info("Wrote %s", path)
    return path


def write_summary_text(
    path: Path,
    *,
    pcap: Path,
    comm: dict[str, Any],
    proto: dict[str, Any],
    traffic: dict[str, Any],
    cmd: dict[str, Any],
    baseline: dict[str, Any],
) -> Path:
    """Short executive summary for SOC handoff."""
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines.append("OT/ICS Behavioral Baseline Summary")
    lines.append("==================================")
    lines.append(f"Generated (UTC): {now}")
    lines.append(f"PCAP: {pcap.resolve()}")
    lines.append("")

    summ = comm.get("summary") or {}
    lines.append("Communication")
    lines.append(f"  Unique hosts: {summ.get('unique_hosts', 'n/a')}")
    lines.append(f"  Unique directed edges: {summ.get('unique_edges', 'n/a')}")
    top = (comm.get("top_hosts_by_volume") or [])[:5]
    if top:
        lines.append("  Top hosts by volume (bytes):")
        for h in top:
            lines.append(f"    - {h.get('ip')}: {h.get('total_bytes')} bytes")
    o2m = (comm.get("patterns") or {}).get("one_to_many_sources") or []
    if o2m:
        lines.append(f"  One-to-many sources (sample): {len(o2m)}")
        for row in o2m[:3]:
            lines.append(f"    - {row.get('src_ip')}: {row.get('distinct_destinations')} peers")
    lines.append("")

    tot = proto.get("totals") or {}
    lines.append("Protocols")
    lines.append(f"  Total packets: {tot.get('packets', 'n/a')}")
    lines.append(f"  ICS-labeled (TCP port heuristic) ratio: {tot.get('ics_packet_ratio', 'n/a')}")
    for row in proto.get("layer4_distribution") or []:
        lines.append(f"  {row.get('family')}: {row.get('packets')} pkts ({row.get('packet_percent')}%)")
    lines.append("")

    agg = traffic.get("aggregate") or {}
    lines.append("Traffic profile")
    lines.append(f"  Mean PPS: {agg.get('mean_packets_per_second')}  Peak PPS: {agg.get('peak_packets_per_second')}")
    lines.append(f"  Mean BPS (bytes/s): {agg.get('mean_bytes_per_second')}  Peak: {agg.get('peak_bytes_per_second')}")
    sp = traffic.get("anomalies") or {}
    lines.append(f"  Spike seconds flagged: {len(sp.get('spikes') or [])}")
    lines.append(f"  Drop seconds flagged: {len(sp.get('drops') or [])}")
    ph = traffic.get("polling_hint") or {}
    lines.append(f"  Polling hint: {ph.get('note', '')}")
    lines.append("")

    ct = cmd.get("totals") or {}
    lines.append("Modbus command profile (TCP/502 heuristic)")
    lines.append(f"  PDUs parsed: {ct.get('modbus_pdus_parsed', 0)}")
    lines.append(f"  Read-like / write-like / other: {ct.get('classified_read_like')} / {ct.get('classified_write_like')} / {ct.get('classified_other')}")
    flags = cmd.get("flags") or {}
    lines.append(f"  ICS write activity flag: {flags.get('ics_write_activity')}")
    if flags.get("rare_function_codes"):
        lines.append(f"  Rare function codes (count): {len(flags['rare_function_codes'])}")
    lines.append("")

    lines.append("Baseline comparison")
    if baseline.get("baseline_loaded"):
        lines.append(f"  New devices: {len(baseline.get('new_devices') or [])}")
        lines.append(f"  New communication pairs: {len(baseline.get('new_communication_pairs') or [])}")
        tr = baseline.get("traffic") or {}
        lines.append(f"  Traffic increase flag: {tr.get('anomalous_traffic_increase')}")
        mw = baseline.get("modbus_writes") or {}
        lines.append(f"  Modbus write anomaly flag: {mw.get('ics_write_activity_flag')}")
    else:
        lines.append(f"  {baseline.get('note', 'No baseline directory provided.')}")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("Wrote %s", path)
    return path
