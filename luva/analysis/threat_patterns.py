"""Aggregate OT-focused threat-pattern hints from flows, assets, and deep_survey (passive PCAP context)."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Optional

from luva.models.asset import Asset, DeviceRole
from luva.models.flow import NetworkFlow

# IT remote-admin / lateral movement ports observed inside a capture (heuristic labels only).
_IT_EDGE_PORTS: dict[int, str] = {
    445: "SMB",
    139: "NetBIOS/SMB",
    135: "MS-RPC",
    3389: "RDP",
    22: "SSH",
    5985: "WinRM",
    5986: "WinRM-SSL",
    23: "Telnet",
    21: "FTP-control",
}

# ICS application ports used for “sequential access” / enumeration heuristics.
_ICS_APP_PORTS: frozenset[int] = frozenset(
    {502, 102, 2404, 20000, 4840, 44818, 47808, 9600, 18245, 18246},
)

_MODBUS_WRITE_CRITICAL: frozenset[int] = frozenset({5, 6, 15, 16})
_MODBUS_FILE_FCS: frozenset[int] = frozenset({20, 21})  # Read/Write File Record — firmware/config transfer pattern

_S7_WRITE_VAR = 0x05
_S7_DOWNLOAD_FAMILY: frozenset[int] = frozenset({0x1A, 0x1B, 0x1C, 0x1D})
_S7_MODE_FAMILY: frozenset[int] = frozenset({0x28, 0x29})

_ENGINEERING_ROLES: frozenset[DeviceRole] = frozenset(
    {
        DeviceRole.ENG_STATION,
        DeviceRole.HMI,
        DeviceRole.SCADA_SERVER,
        DeviceRole.GATEWAY,
    },
)


def _asset_map(assets: list[Asset]) -> dict[str, Asset]:
    return {a.ip_address: a for a in assets if a.ip_address}


def build_threat_pattern_report(
    flows: list[NetworkFlow],
    assets: list[Asset],
    deep_survey: dict[str, Any],
) -> dict[str, Any]:
    """Structured hints for reports — not proof of malicious intent."""
    ast = _asset_map(assets)
    hints = deep_survey.get("threat_hints") or {}

    modbus_writes: list[dict[str, Any]] = []
    s7_critical: list[dict[str, Any]] = []
    for f in flows:
        if f.modbus_write_fcs_seen:
            fc_interpret: list[str] = []
            for fc in sorted(f.modbus_write_fcs_seen):
                if fc in _MODBUS_WRITE_CRITICAL:
                    fc_interpret.append(f"FC{fc} write (coil/register)")
                elif fc in _MODBUS_FILE_FCS:
                    fc_interpret.append(f"FC{fc} file-record (possible config/firmware transfer)")
                elif fc in (22, 23):
                    fc_interpret.append(f"FC{fc} mask/read-write registers")
                else:
                    fc_interpret.append(f"FC{fc} write-family")
            modbus_writes.append(
                {
                    "flow_id": f.flow_id,
                    "src_ip": f.src_ip,
                    "dst_ip": f.dst_ip,
                    "src_port": f.src_port,
                    "dst_port": f.dst_port,
                    "write_function_codes": sorted(f.modbus_write_fcs_seen),
                    "interpretation": "; ".join(fc_interpret),
                    "packet_count": f.packet_count,
                },
            )
        s7_codes = f.s7_service_codes_seen
        if not s7_codes:
            continue
        tags: list[str] = []
        if _S7_WRITE_VAR in s7_codes:
            tags.append("Job Write Variable (0x05)")
        if s7_codes & _S7_DOWNLOAD_FAMILY:
            tags.append("Program download / block transfer (0x1A–0x1D family)")
        if s7_codes & _S7_MODE_FAMILY:
            tags.append("PLC control / STOP-RUN family (0x28/0x29)")
        if tags:
            s7_critical.append(
                {
                    "flow_id": f.flow_id,
                    "src_ip": f.src_ip,
                    "dst_ip": f.dst_ip,
                    "src_port": f.src_port,
                    "dst_port": f.dst_port,
                    "s7_service_codes_hex": [f"0x{c:02X}" for c in sorted(s7_codes)],
                    "interpretation": "; ".join(tags),
                    "packet_count": f.packet_count,
                },
            )

    modbus_writes.sort(key=lambda x: x["packet_count"], reverse=True)
    s7_critical.sort(key=lambda x: x["packet_count"], reverse=True)

    it_in_ot: list[dict[str, Any]] = []
    for f in flows:
        label = _IT_EDGE_PORTS.get(f.dst_port) or _IT_EDGE_PORTS.get(f.src_port)
        if not label:
            continue
        port = f.dst_port if f.dst_port in _IT_EDGE_PORTS else f.src_port
        it_in_ot.append(
            {
                "flow_id": f.flow_id,
                "service_guess": label,
                "port": port,
                "src_ip": f.src_ip,
                "dst_ip": f.dst_ip,
                "transport": f.transport_protocol,
                "packet_count": f.packet_count,
            },
        )
    it_in_ot.sort(key=lambda x: x["packet_count"], reverse=True)

    # Same source touching many distinct ICS destinations (possible scan or pivot).
    src_to_ics_dsts: dict[str, set[str]] = defaultdict(set)
    for f in flows:
        if f.dst_port in _ICS_APP_PORTS:
            src_to_ics_dsts[f.src_ip].add(f.dst_ip)
        if f.src_port in _ICS_APP_PORTS:
            src_to_ics_dsts[f.dst_ip].add(f.src_ip)
    sequential_hints: list[dict[str, Any]] = []
    for src_ip, dsts in src_to_ics_dsts.items():
        if len(dsts) >= 4:
            a = ast.get(src_ip)
            role = a.role.value if a and a.role else "Unknown"
            sequential_hints.append(
                {
                    "src_ip": src_ip,
                    "unique_ics_peer_count": len(dsts),
                    "sample_destinations": sorted(dsts)[:12],
                    "asset_role_guess": role,
                    "note": "Single host talks to many ICS ports/hosts — review for enumeration or compromised jump host.",
                },
            )
    sequential_hints.sort(key=lambda x: x["unique_ics_peer_count"], reverse=True)

    # Modbus reads from hosts not tagged as engineering/HMI/SCADA (weak heuristic).
    unauth_read_hints: list[dict[str, Any]] = []
    for f in flows:
        if "Modbus" not in (f.ics_protocol or "") and "Modbus" not in f.ics_protocols_seen:
            continue
        if f.modbus_write_fcs_seen:
            continue
        if not (f.function_codes_seen & {3, 4}):
            continue
        a = ast.get(f.src_ip)
        role = a.role if a else None
        if role is None or role == DeviceRole.UNKNOWN or role not in _ENGINEERING_ROLES:
            unauth_read_hints.append(
                {
                    "flow_id": f.flow_id,
                    "src_ip": f.src_ip,
                    "dst_ip": f.dst_ip,
                    "dst_port": f.dst_port,
                    "function_codes_seen": sorted(f.function_codes_seen),
                    "packet_count": f.packet_count,
                    "asset_role_guess": role.value if role else "Unknown",
                    "note": "Modbus read (FC 3/4) from non-engineering-tagged source — validate against authorized HMIs/engineering stations.",
                },
            )
    unauth_read_hints.sort(key=lambda x: x["packet_count"], reverse=True)
    unauth_read_hints = unauth_read_hints[:40]

    tb = deep_survey.get("tcp_behavior") or {}
    syn_only = int(tb.get("syn_without_ack_segments") or 0)
    total_payload_tcp = max(int(tb.get("segments_with_payload") or 0), 1)
    syn_ratio = round(syn_only / total_payload_tcp, 4) if total_payload_tcp else 0.0

    executive_findings: list[dict[str, str]] = []
    if modbus_writes:
        executive_findings.append(
            {
                "severity": "CRITICAL",
                "title": "Modbus write operations (FC 5/6/15/16 and related)",
                "detail": f"{len(modbus_writes)} flow(s) carry Modbus write-family function codes — verify maintenance windows and authorized engineering sources.",
            },
        )
    if s7_critical:
        executive_findings.append(
            {
                "severity": "CRITICAL",
                "title": "S7 write, download, or PLC control/stop traffic",
                "detail": f"{len(s7_critical)} flow(s) show S7 Job Write, download block, or PLC control/stop class services — correlate with change tickets.",
            },
        )
    if it_in_ot:
        executive_findings.append(
            {
                "severity": "HIGH",
                "title": "IT remote protocols present (SMB / RDP / SSH / WinRM / …)",
                "detail": f"{len(it_in_ot)} flow(s) on classic IT lateral-movement ports — map to jump hosts and segmentation intent.",
            },
        )
    if sequential_hints:
        executive_findings.append(
            {
                "severity": "HIGH",
                "title": "Possible ICS host enumeration (one source, many OT targets)",
                "detail": f"{len(sequential_hints)} source IP(s) speak to ≥4 distinct OT peers on ICS ports.",
            },
        )
    if syn_only > 200 and syn_ratio > 0.15:
        executive_findings.append(
            {
                "severity": "MEDIUM",
                "title": "Elevated TCP SYN-only segments (possible scan or half-open noise)",
                "detail": f"{syn_only} SYN-without-ACK segments ({syn_ratio:.1%} of TCP payload segments) — normal OT rarely port-scans; validate with IDS.",
            },
        )
    scan_strings = hints.get("scanner_tool_string_hits") or {}
    if scan_strings:
        executive_findings.append(
            {
                "severity": "HIGH",
                "title": "Scanner/tool fingerprints in cleartext payloads",
                "detail": f"Strings suggest scanner or automation tools: {scan_strings}",
            },
        )
    creds = hints.get("credential_exposure_samples") or []
    if creds:
        executive_findings.append(
            {
                "severity": "HIGH",
                "title": "Cleartext credential patterns (HTTP Basic, FTP USER, …)",
                "detail": f"{len(creds)} sample(s) in deep_survey.threat_hints — rotate secrets if confirmed.",
            },
        )
    repeats = hints.get("repeated_tcp_payload_fingerprints") or []
    if repeats:
        executive_findings.append(
            {
                "severity": "LOW",
                "title": "Repeated identical TCP payload prefixes (replay / polling fingerprint)",
                "detail": f"{len(repeats)} hash bucket(s) with ≥4 occurrences — may be normal polling; compare timing in PCAP.",
            },
        )

    arp_n = int(hints.get("arp_frames_observed") or 0)
    bcast_n = int(hints.get("ipv4_broadcast_dest_packets") or 0)
    storm_note: Optional[str] = None
    if arp_n > 5_000 or bcast_n > 2_000:
        storm_note = (
            f"High ARP ({arp_n}) or IPv4 broadcast ({bcast_n}) packet counts — check for storms or misconfiguration (passive count only)."
        )
        executive_findings.append(
            {
                "severity": "MEDIUM",
                "title": "Possible broadcast/ARP noise",
                "detail": storm_note,
            },
        )

    limitations = [
        "No live process-variable baselines: setpoint / physics-plausibility spikes (e.g. temperature step changes) require time-series register tracking not implemented here.",
        "Replay/injection verdicts need full TCP reassembly; duplicate payload hashes are hints only.",
        "Asset roles are heuristics — “unauthorized read” is a hypothesis for analysts.",
    ]

    return {
        "report_version": "1.0",
        "modbus_write_flows": modbus_writes[:60],
        "s7_critical_flows": s7_critical[:60],
        "it_remote_protocol_flows": it_in_ot[:80],
        "sequential_ics_access_hints": sequential_hints[:25],
        "modbus_read_non_engineering_hints": unauth_read_hints,
        "discovery_and_scanning": {
            "tcp_syn_without_ack_segments": syn_only,
            "syn_to_tcp_payload_ratio": syn_ratio,
            "scanner_tool_string_hits": scan_strings,
            "notes": "OT networks rarely show sustained SYN scanning; ratio is a coarse hint.",
        },
        "credential_and_broadcast": {
            "credential_exposure_sample_count": len(creds),
            "arp_frames_observed": arp_n,
            "ipv4_broadcast_dest_packets": bcast_n,
            "broadcast_storm_note": storm_note,
        },
        "replay_and_duplicate_payloads": {
            "repeated_fingerprint_buckets": repeats,
            "note": "MD5 of first 48 bytes of cleartext TCP payloads; same hash ≥4 times in capture.",
        },
        "passive_asset_inventory_note": (
            "PLC/HMI/RTU list, vendors, topology, and partial firmware hints already come from assets, flows, "
            "topology.graphml, and banner/deep_survey fields — this section adds threat-oriented roll-ups only."
        ),
        "limitations": limitations,
        "executive_findings": executive_findings,
        "summary_counts": {
            "modbus_write_flows": len(modbus_writes),
            "s7_critical_flows": len(s7_critical),
            "it_remote_protocol_flows": len(it_in_ot),
            "sequential_ics_sources": len(sequential_hints),
            "modbus_read_non_engineering_flows": len(unauth_read_hints),
        },
    }
