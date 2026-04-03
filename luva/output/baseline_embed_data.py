"""
Map a full Luva ``REPORT`` dict into the JSON bundle expected by the embedded Baseline SOC UI.

The same four top-level objects match SIEM/archival bundles; values here are
derived from flows, statistics.deep_survey, statistics.flow_stats, and threat hints so one HTML
file stays self-contained.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

WRITE_FCS = frozenset({5, 6, 15, 16, 22, 24})
IT_PORTS = {22, 23, 25, 53, 80, 135, 139, 443, 445, 3389, 5900, 5985, 5986}


def _pct_threshold(counts: list[int], percentile: float) -> float:
    if not counts:
        return 0.0
    s = sorted(counts)
    i = min(int(len(s) * percentile / 100.0), len(s) - 1)
    return float(s[max(0, i)])


def build_baseline_embed_bundle(report: dict[str, Any]) -> dict[str, Any]:
    """Return ``{communication_map, protocol_distribution, traffic_profile, command_profile}``."""
    meta = report.get("metadata") or {}
    flows = report.get("flows") or []
    stats = report.get("statistics") or {}
    deep = stats.get("deep_survey") or {}
    fs = stats.get("flow_stats") or {}
    proto_dist = stats.get("protocol_distribution") or {}
    threat = stats.get("threat_patterns") or {}

    # --- communication_map (aggregate flows by src/dst) ---
    edge_pkt: dict[tuple[str, str], int] = defaultdict(int)
    edge_bytes: dict[tuple[str, str], int] = defaultdict(int)
    host_bytes: dict[str, int] = defaultdict(int)
    src_peers: dict[str, set[str]] = defaultdict(set)

    for f in flows:
        s, d = f.get("src_ip"), f.get("dst_ip")
        if not s or not d:
            continue
        pk = int(f.get("packet_count") or 0)
        by = int(f.get("byte_count") or 0)
        edge_pkt[(s, d)] += pk
        edge_bytes[(s, d)] += by
        host_bytes[s] += by
        host_bytes[d] += by
        src_peers[s].add(d)

    edges = [
        {"src_ip": a, "dst_ip": b, "packets": edge_pkt[(a, b)], "bytes": edge_bytes[(a, b)]}
        for a, b in sorted(edge_pkt.keys(), key=lambda k: -edge_pkt[k])
    ]
    hosts = set()
    for a, b in edge_pkt:
        hosts.add(a)
        hosts.add(b)

    counts = [edge_pkt[k] for k in edge_pkt]
    rare_thr = _pct_threshold(counts, 10.0)
    rare_edges = [
        {"src_ip": a, "dst_ip": b, "packets": edge_pkt[(a, b)], "bytes": edge_bytes[(a, b)]}
        for a, b in edge_pkt
        if edge_pkt[(a, b)] <= rare_thr and edge_pkt[(a, b)] > 0
    ]
    rare_edges.sort(key=lambda x: x["packets"])

    one_to_many = [
        {"src_ip": src, "distinct_destinations": len(peers), "sample_peers": sorted(peers)[:16]}
        for src, peers in src_peers.items()
        if len(peers) >= 8
    ]
    one_to_many.sort(key=lambda x: -x["distinct_destinations"])

    top_hosts = sorted(host_bytes.items(), key=lambda x: -x[1])[:50]
    hosts_out = [
        {"ip": ip, "total_bytes": b, "distinct_peers_as_src": len(src_peers.get(ip, ()))}
        for ip, b in top_hosts
    ]

    tp_it = threat.get("it_remote_protocol_flows") or []
    it_samples: list[dict[str, Any]] = []
    for row in tp_it[:80] if isinstance(tp_it, list) else []:
        if isinstance(row, dict):
            sp = row.get("port") or row.get("dst_port")
            it_samples.append(
                {
                    "note": "it_style_port_on_tcp",
                    "port": int(sp) if sp is not None else 0,
                    "service_hint": row.get("service_guess") or row.get("service_hint") or str(sp),
                    "src_ip": row.get("src_ip", ""),
                    "dst_ip": row.get("dst_ip", ""),
                },
            )
    if not it_samples:
        for row in deep.get("top_destination_tcp_ports") or []:
            p = int(row.get("port") or 0)
            if p in IT_PORTS:
                it_samples.append(
                    {
                        "note": "it_style_port_on_tcp",
                        "port": p,
                        "service_hint": row.get("service") or str(p),
                        "src_ip": "",
                        "dst_ip": "",
                    },
                )

    comm = {
        "meta": {
            "tool": "luva_baseline_embed",
            "pcap_path": " · ".join(meta.get("input_files") or []) or meta.get("analysis_timestamp", ""),
            "generated_utc": meta.get("analysis_timestamp", ""),
        },
        "edges": edges,
        "summary": {
            "unique_edges": len(edge_pkt),
            "unique_hosts": len(hosts),
            "rare_edge_percentile_threshold": rare_thr,
            "rare_edge_definition": "packet_count <= p10 of all edges (from Luva flows)",
        },
        "top_hosts_by_volume": hosts_out,
        "patterns": {
            "one_to_many_sources": one_to_many[:40],
            "rare_low_volume_edges": rare_edges[:200],
        },
        "baseline_comparison": {
            "baseline_loaded": False,
            "note": "Embedded in Luva HTML — compare captures with ot_baseline CLI + --baseline-dir for deltas.",
        },
    }

    # --- protocol_distribution ---
    ip_protos = deep.get("ip_protocols") or {}
    tcp_n = int(ip_protos.get("TCP") or 0)
    udp_n = int(ip_protos.get("UDP") or 0)
    icmp_n = int(ip_protos.get("ICMP") or 0) + int(ip_protos.get("ICMPv6") or 0)
    other_n = max(int(meta.get("total_packets") or 0) - tcp_n - udp_n - icmp_n, 0)
    total_pk = max(int(meta.get("total_packets") or 1), 1)

    l4_rows = []
    for fam, n in (("tcp", tcp_n), ("udp", udp_n), ("icmp", icmp_n), ("other", other_n)):
        if n <= 0 and fam != "tcp":
            continue
        l4_rows.append(
            {
                "family": fam,
                "packets": n,
                "bytes": 0,
                "packet_percent": round(100.0 * n / total_pk, 4),
            },
        )
    if not l4_rows or sum(r["packets"] for r in l4_rows) == 0:
        tp_fallback = int(meta.get("total_packets") or fs.get("total_packets") or 0)
        if tp_fallback > 0:
            l4_rows = [
                {
                    "family": "ipv4_traffic",
                    "packets": tp_fallback,
                    "bytes": int(fs.get("total_bytes") or 0),
                    "packet_percent": 100.0,
                },
            ]
            total_pk = tp_fallback

    ics_pkt = 0
    for f in flows:
        if f.get("ics_protocol") or f.get("ics_protocols"):
            ics_pkt += int(f.get("packet_count") or 0)
    if ics_pkt == 0:
        ics_pkt = sum(int(v) for k, v in proto_dist.items() if k and str(k) not in ("TCP", "UDP", "ICMP"))
    non_ics = max(total_pk - ics_pkt, 0)
    ics_by_protocol = [{"slug": str(k), "packets": int(v), "bytes": 0} for k, v in proto_dist.items()]

    proto = {
        "meta": comm["meta"],
        "layer4_distribution": l4_rows,
        "totals": {
            "packets": total_pk,
            "ics_labeled_packets": min(ics_pkt, total_pk),
            "non_ics_labeled_packets": non_ics,
            "ics_packet_ratio": round(min(ics_pkt, total_pk) / total_pk, 6) if total_pk else 0.0,
        },
        "ics_by_protocol": ics_by_protocol[:32],
        "anomaly_hints": {
            "it_style_tcp_sessions_sample": it_samples[:500],
            "note": "From Luva threat_patterns / deep_survey heuristics.",
        },
    }

    # --- traffic_profile (minute bins from deep_survey.timeline) ---
    tl = deep.get("timeline") or {}
    vals = tl.get("packets") or []
    per_second: list[dict[str, Any]] = []
    total_b = int(fs.get("total_bytes") or 0)
    total_p = int(fs.get("total_packets") or 1)
    bpp = total_b / total_p if total_p else 0
    spike_set: set[int] = set()
    if vals:
        mean_v = sum(vals) / len(vals)
        for i, v in enumerate(vals):
            pps_est = int(v / 60) if v else 0
            per_second.append(
                {
                    "t_offset_sec": i * 60,
                    "packets_per_second": pps_est,
                    "bytes_per_second": int(bpp * pps_est),
                    "bits_per_second": int(bpp * pps_est * 8),
                },
            )
            if mean_v >= 5 and v >= 3 * mean_v:
                spike_set.add(i * 60)
    spikes = [{"t_offset_sec": t, "pps": next((p["packets_per_second"] for p in per_second if p["t_offset_sec"] == t), 0), "rolling_mean_pps": round(mean_v / 60, 2) if vals else 0} for t in sorted(spike_set)[:200]]

    traffic = {
        "meta": comm["meta"],
        "per_second": per_second,
        "aggregate": {
            "duration_seconds_observed": len(vals) * 60 if vals else 0,
            "mean_packets_per_second": round(sum(p["packets_per_second"] for p in per_second) / len(per_second), 4) if per_second else 0,
            "peak_packets_per_second": max((p["packets_per_second"] for p in per_second), default=0),
            "mean_bytes_per_second": round(sum(p["bytes_per_second"] for p in per_second) / len(per_second), 4) if per_second else 0,
            "peak_bytes_per_second": max((p["bytes_per_second"] for p in per_second), default=0),
            "mean_bits_per_second": 0,
            "peak_bits_per_second": 0,
        },
        "anomalies": {
            "spike_threshold": "3x mean packets/min bin",
            "spikes": spikes,
            "drops": [],
            "drop_threshold": "n/a",
        },
        "polling_hint": {
            "note": (stats.get("periodic_flows") or []) and "See ICS flows → periodic table in main report." or "From deep_survey timeline bins.",
            "active_second_packet_cv": None,
        },
    }

    # --- command_profile (Modbus FC from flows) ---
    fc_counts: dict[int, int] = defaultdict(int)
    fc_sources: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    write_sources: set[str] = set()
    read_like = write_like = other_like = 0

    for f in flows:
        src = f.get("src_ip") or ""
        fcs = f.get("function_codes_seen") or []
        mw = f.get("modbus_write_fcs_seen") or []
        pk = int(f.get("packet_count") or 0)
        nfc = max(len(fcs), 1)
        share = max(pk // nfc, 1) if fcs else 0
        for fc in fcs:
            fc_int = int(fc)
            fc_counts[fc_int] += share
            fc_sources[fc_int][src] += share
        for fc in mw:
            write_sources.add(src)
            fi = int(fc)
            fc_counts[fi] = fc_counts.get(fi, 0) + max(pk // max(len(mw), 1), 1)
            fc_sources[fi][src] += max(pk // max(len(mw), 1), 1)
        if f.get("has_write_operations"):
            write_sources.add(src)
        if mw:
            write_like += pk
        elif fcs:
            read_like += pk
        elif f.get("ics_protocol") == "Modbus" or "Modbus" in (f.get("ics_protocols") or []):
            other_like += pk

    total_m = sum(fc_counts.values()) or 1
    by_fc = []
    for fc, n in sorted(fc_counts.items(), key=lambda x: -x[1]):
        rare = n <= max(1, int(total_m * 0.002))
        top_src = sorted(fc_sources[fc].items(), key=lambda x: -x[1])[:8]
        by_fc.append(
            {
                "function_code": fc,
                "count": n,
                "percent_of_modbus_pdus": round(100.0 * n / total_m, 4),
                "top_sources": top_src,
                "flag_rare": rare,
            },
        )

    cmd = {
        "meta": comm["meta"],
        "scope": "luva_flow_aggregates_modbus_heuristic",
        "totals": {
            "modbus_pdus_parsed": total_m,
            "classified_read_like": read_like,
            "classified_write_like": write_like,
            "classified_other": other_like,
        },
        "write_source_ips": sorted(write_sources),
        "function_codes": by_fc,
        "flags": {
            "rare_function_codes": [r for r in by_fc if r["flag_rare"]],
            "uncommon_under_one_percent": [r for r in by_fc if r["percent_of_modbus_pdus"] < 1.0 and r["count"] > 0],
            "ics_write_activity": len(write_sources) > 0,
            "note": "Counts inferred from Luva flow aggregates (not per-PDU like ot_baseline).",
        },
    }

    return {
        "communication_map": comm,
        "protocol_distribution": proto,
        "traffic_profile": traffic,
        "command_profile": cmd,
    }
