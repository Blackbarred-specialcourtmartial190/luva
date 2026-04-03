"""Structured audit / pentest workbook: findings, MITRE mapping, remediation, attack surface."""

from __future__ import annotations

from typing import Any, Optional

from luva.core.config import Severity
from luva.models.asset import Asset
from luva.models.event import AnomalyEvent
from luva.models.flow import NetworkFlow
from luva.utils.ip_utils import is_private_ipv4, is_public_ipv4


def _mitre(id_: str, name: str, matrix: str = "ICS") -> dict[str, str]:
    base, _, sub = id_.partition(".")
    if sub:
        url = f"https://attack.mitre.org/techniques/{base}/{sub}/"
    else:
        url = f"https://attack.mitre.org/techniques/{base}/"
    return {"id": id_, "name": name, "matrix": matrix, "url": url}


# Heuristic ATT&CK references — validate against engagement scope and plant docs.
_MITRE_WRITE = [_mitre("T0855", "Unauthorized Command Message")]
_MITRE_EXCEPTION = [_mitre("T0869", "Standard Application Layer Protocol")]
_MITRE_SEGMENT = [
    _mitre("T0886", "Exploitation of Remote Services"),
    _mitre("T0846", "Remote System Discovery"),
]
_MITRE_TELNET = [_mitre("T0807", "Command-Line Interface")]
_MITRE_FTP = [_mitre("T0869", "Standard Application Layer Protocol")]
_MITRE_SYN = [_mitre("T0846", "Remote System Discovery")]
_MITRE_REMOTE_ADMIN = [_mitre("T0822", "External Remote Services")]
_MITRE_SNMP = [_mitre("T0869", "Standard Application Layer Protocol")]
_MITRE_HTTP = [_mitre("T1071", "Application Layer Protocol", matrix="Enterprise")]
_MITRE_SSH = [_mitre("T1021", "Remote Services", matrix="Enterprise")]


def build_audit_workbook(
    flows: list[NetworkFlow],
    assets: list[Asset],
    anomalies: list[AnomalyEvent],
    deep_survey: dict[str, Any],
    pentest: dict[str, Any],
    threat_patterns: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Evidence-oriented workbook for security assessors (passive PCAP context only)."""
    findings: list[dict[str, Any]] = []
    fid = 0

    def add(
        severity: str,
        category: str,
        title: str,
        narrative: str,
        evidence: str,
        mitre: list[dict[str, str]],
        remediation: str,
        standards_refs: list[str],
    ) -> None:
        nonlocal fid
        fid += 1
        findings.append(
            {
                "finding_id": f"AUD-{fid:03d}",
                "severity": severity,
                "category": category,
                "title": title,
                "narrative": narrative,
                "evidence_summary": evidence,
                "mitre_attack_references": mitre,
                "remediation": remediation,
                "standards_refs": standards_refs,
            },
        )

    writers = {f.src_ip for f in flows if f.has_write_operations and f.src_ip}
    if writers:
        add(
            "HIGH",
            "WRITE_SURFACE",
            "ICS/OT write-capable sessions observed",
            "One or more sources performed application-layer write operations on industrial protocols in the capture.",
            f"{len(writers)} distinct source IP(s) with write activity; correlate with maintenance windows and authorized engineering hosts.",
            _MITRE_WRITE,
            "Inventory write-capable hosts; enforce jump hosts and recording; restrict HMIs/engineering VLANs; monitor T0855-style command patterns.",
            ["IEC 62443-3-3 SR 5.2 (network segmentation)", "SR 3.4 (data confidentiality)"],
        )

    exc_flows = [f for f in flows if f.exception_count > 0]
    if exc_flows:
        add(
            "MEDIUM",
            "PROTOCOL_HEALTH",
            "Protocol exception / error responses in ICS flows",
            "Elevated exception counters may indicate faults, version skew, or abusive probing.",
            f"{len(exc_flows)} flow(s) with non-zero exception counters (sample in pentest_insights.flows_with_exceptions).",
            _MITRE_EXCEPTION,
            "Review PLC/HMI logs; validate firmware and configuration; rule out unauthorized test tools on the segment.",
            ["IEC 62443-3-3 SR 7.1 (resource availability)"],
        )

    cross_segment_flows: list[NetworkFlow] = []
    for f in flows:
        if not f.src_ip or not f.dst_ip:
            continue
        sp, dp = is_private_ipv4(f.src_ip), is_private_ipv4(f.dst_ip)
        sg, dg = is_public_ipv4(f.src_ip), is_public_ipv4(f.dst_ip)
        if (sp and dg) or (sg and dp):
            cross_segment_flows.append(f)
    if cross_segment_flows:
        add(
            "HIGH",
            "SEGMENTATION",
            "Private and public IP endpoints in the same flows",
            "Traffic patterns suggest paths between RFC1918 space and routable addresses — verify intended architecture and firewall posture.",
            f"{len(cross_segment_flows)} flow(s) private↔public (sample in pentest_insights.segmentation_observations).",
            _MITRE_SEGMENT,
            "Confirm DMZ and OT boundary design; restrict outbound from PLCs; document any required cloud or remote paths.",
            ["IEC 62443-2-1 (zones/conduits)", "NIST SP 800-82"],
        )

    cleartext = deep_survey.get("cleartext_hints") or {}
    if cleartext.get("telnet_port"):
        add(
            "CRITICAL",
            "CLEARTEXT_REMOTE",
            "Telnet (cleartext remote shell) port traffic",
            "Telnet provides no encryption; credentials and session data are exposed on the wire.",
            "Cleartext fingerprint: telnet_port in deep_survey.",
            _MITRE_TELNET,
            "Disable Telnet; migrate to SSH with key-based auth where remote shell is required; block TCP/23 at boundaries.",
            ["IEC 62443-3-3 SR 4.3 (use of cryptography)", "NIST SP 800-82"],
        )
    if cleartext.get("ftp_banner"):
        add(
            "MEDIUM",
            "CLEARTEXT_REMOTE",
            "FTP service banner observed",
            "FTP commonly carries credentials and payload in cleartext.",
            "FTP banner sample in deep_survey / network tab.",
            _MITRE_FTP,
            "Replace with SFTP/SCP or segmented file drops; block legacy FTP across OT boundaries unless explicitly accepted risk.",
            ["IEC 62443-3-3 SR 4.3"],
        )

    if cleartext.get("ssh_banner"):
        add(
            "LOW",
            "REMOTE_ACCESS_VISIBILITY",
            "SSH banner observed on the segment",
            "SSH is encrypted but remote shell capability increases attack surface if exposed broadly.",
            "SSH banner in cleartext_hints / banner samples.",
            _MITRE_SSH,
            "Restrict SSH to bastion/jump hosts; key-only auth; monitor failed logins and source IPs.",
            ["IEC 62443-3-3 SR 1.13 (access control)"],
        )

    http_n = int(cleartext.get("http_like") or 0)
    if http_n > 0:
        add(
            "LOW",
            "IT_PROTOCOL_IN_OT",
            "HTTP-like cleartext patterns",
            "HTTP in OT may indicate HMI panels, APIs, or mis-placed IT services.",
            f"~{http_n} HTTP-like segment(s) in metadata (deep_survey).",
            _MITRE_HTTP,
            "Prefer HTTPS for management interfaces; segment web UIs from control VLANs; validate certificate pinning where used.",
            ["IEC 62443-3-3 SR 4.3"],
        )

    cot_ot = deep_survey.get("cleartext_ot_sensitive") or {}
    hits_ot = dict(cot_ot.get("hits_by_category") or {})
    samples_ot = list(cot_ot.get("samples") or [])
    if hits_ot or samples_ot:
        hit_total = sum(hits_ot.values())
        risky_ot = frozenset(
            {
                "modbus_tcp_cleartext",
                "iec104_cleartext",
                "snmp_cleartext_community",
                "s7comm_cleartext",
                "dnp3_cleartext",
                "modbus_port_cleartext_non_mbap",
            },
        )
        sev_ot = (
            "HIGH"
            if (risky_ot & set(hits_ot)) or any(s.get("sensitivity") == "HIGH" for s in samples_ot)
            else "MEDIUM"
        )
        mitre_sniff = [
            _mitre("T1040", "Network Sniffing", matrix="Enterprise"),
            _mitre("T0869", "Standard Application Layer Protocol"),
        ]
        add(
            sev_ot,
            "CLEARTEXT_OT_PAYLOAD",
            "Industrial / OT application data visible without TLS",
            "Heuristic packet survey shows ICS-style PDUs, SNMP communities (redacted in samples), or OT-tagged HTTP in cleartext — "
            "passive observers on the segment could recover process or credential material.",
            f"{hit_total} packet-level hit(s), {len(samples_ot)} deduplicated sample row(s); see statistics.deep_survey.cleartext_ot_sensitive.",
            mitre_sniff,
            "Use encrypted transports or VPN overlays where feasible; restrict span ports; inventory engineering laptops; validate jump-host-only access to PLCs.",
            ["IEC 62443-3-3 SR 4.3 (cryptography)", "SR 3.1 (communication integrity)", "NIST SP 800-82"],
        )

    tb = deep_survey.get("tcp_behavior") or {}
    syn_only = int(tb.get("syn_without_ack_segments") or 0)
    if syn_only > 100:
        add(
            "LOW",
            "DISCOVERY_NOISE",
            "Elevated TCP SYN without completing handshake",
            "May reflect port scanning, asymmetric routing, or capture truncation.",
            f"{syn_only} SYN-without-ACK segments (deep_survey.tcp_behavior).",
            _MITRE_SYN,
            "Correlate with IDS and switch ACL logs; confirm no unauthorized discovery from guest or corporate VLANs.",
            ["IEC 62443-3-3 SR 6.2 (event monitoring)"],
        )

    risk_admin_ports = {22, 3389, 5900}
    admin_hosts = [
        a
        for a in assets
        if a.open_ports and (set(a.open_ports) & risk_admin_ports)
    ]
    if admin_hosts:
        sample = ", ".join(sorted({a.ip_address for a in admin_hosts})[:12])
        add(
            "HIGH",
            "REMOTE_ADMIN_EXPOSURE",
            "Remote administration ports open on discovered hosts",
            "SSH, RDP, or VNC listeners on OT-visible IPs increase lateral movement options after initial compromise.",
            f"{len(admin_hosts)} asset(s); sample IPs: {sample}" + (" …" if len(admin_hosts) > 12 else ""),
            _MITRE_REMOTE_ADMIN,
            "Remove direct internet exposure; use bastion + MFA; restrict by source IP; disable unused remote admin services.",
            ["IEC 62443-3-3 SR 1.13", "SR 3.1 (communication integrity)"],
        )

    ext_assets = [a for a in assets if a.ip_address and is_public_ipv4(a.ip_address)]
    if ext_assets:
        sample = ", ".join(sorted({a.ip_address for a in ext_assets})[:10])
        add(
            "HIGH",
            "EXTERNAL_FACING",
            "Public IPv4 addresses assigned to discovered assets",
            "OT hosts with public addresses may be directly reachable from the Internet unless fronted by strict controls.",
            f"{len(ext_assets)} asset(s); sample: {sample}",
            _MITRE_REMOTE_ADMIN,
            "Validate addressing plan; move controls behind VPN/zero-trust; ensure no PLC/HMI is unintentionally routable.",
            ["NIST SP 800-82", "IEC 62443-2-1"],
        )

    snmp_assets = [a for a in assets if "SNMP" in (a.protocols_seen or set()) or ({161, 162} & set(a.open_ports or set()))]
    if snmp_assets:
        add(
            "MEDIUM",
            "MANAGEMENT_PLANE",
            "SNMP visible on OT endpoints",
            "Community strings and MIB exposure are common abuse paths; v2c is cleartext.",
            f"{len(snmp_assets)} asset(s) with SNMP traffic or ports 161/162.",
            _MITRE_SNMP,
            "Prefer SNMPv3 with auth+priv; rotate communities; ACL SNMP to NMS only; disable write where not required.",
            ["IEC 62443-3-3 SR 4.3", "SR 3.1"],
        )

    crit_anom = sum(1 for e in anomalies if e.severity == Severity.CRITICAL)
    high_anom = sum(1 for e in anomalies if e.severity == Severity.HIGH)
    if crit_anom or high_anom:
        add(
            "HIGH" if crit_anom else "MEDIUM",
            "DETECTION_ENGINE",
            "Rule engine reported high-severity anomalies",
            "YAML/statistical detectors flagged events that require analyst triage — not proof of compromise alone.",
            f"{crit_anom} CRITICAL, {high_anom} HIGH anomaly event(s). See anomalies.csv / Anomalies tab.",
            _MITRE_EXCEPTION,
            "Triage each event with PCAP context and asset owner; tune or document accepted baselines; export evidence packets if needed.",
            ["IEC 62443-3-3 SR 6.2"],
        )

    th = threat_patterns or {}
    sct = th.get("summary_counts") or {}
    if sct.get("modbus_write_flows"):
        add(
            "CRITICAL",
            "MODBUS_WRITE_TRAFFIC",
            "Modbus write-family function codes observed (FC 5/6/15/16 and related)",
            "Coil/register writes change physical or logical process state; confirm source is an authorized engineering or HMI host.",
            f"{sct.get('modbus_write_flows', 0)} flow(s) with Modbus writes — see statistics.threat_patterns.modbus_write_flows.",
            _MITRE_WRITE,
            "Restrict write-capable hosts; use read-only HMIs where possible; log and alarm on writes outside maintenance windows.",
            ["IEC 62443-3-3 SR 5.2", "SR 1.12"],
        )
    if sct.get("s7_critical_flows"):
        add(
            "CRITICAL",
            "S7_CRITICAL_SERVICES",
            "S7 Job Write, download, or PLC control/stop class services in capture",
            "Program transfer and PLC mode changes are high-impact; correlate with change management.",
            f"{sct.get('s7_critical_flows', 0)} flow(s) — see statistics.threat_patterns.s7_critical_flows.",
            _MITRE_WRITE,
            "Segment engineering VLANs; monitor TIA portal access; validate PLC checksums after maintenance.",
            ["IEC 62443-2-4", "NIST SP 800-82"],
        )
    if sct.get("it_remote_protocol_flows"):
        add(
            "HIGH",
            "IT_REMOTE_IN_OT_CAPTURE",
            "SMB / RDP / SSH / WinRM-class ports seen in the same capture as OT traffic",
            "Classic lateral-movement protocols on OT segments warrant jump-host and segmentation review.",
            f"{sct.get('it_remote_protocol_flows', 0)} flow(s) — see statistics.threat_patterns.it_remote_protocol_flows.",
            _MITRE_REMOTE_ADMIN + _MITRE_SSH,
            "Prefer dedicated bastions; disable SMB where unnecessary; restrict RDP/SSH by source and MFA.",
            ["IEC 62443-3-3 SR 1.13"],
        )
    if sct.get("sequential_ics_sources"):
        add(
            "HIGH",
            "ICS_MULTI_TARGET_SOURCE",
            "One source IP contacted many distinct OT peers on ICS ports",
            "May indicate scanning, misconfigured client, or compromised workstation touching many PLCs.",
            f"{sct.get('sequential_ics_sources', 0)} source(s) — see statistics.threat_patterns.sequential_ics_access_hints.",
            _MITRE_SEGMENT,
            "Review source asset inventory; compare to known SCADA clients; inspect for scanner fingerprints in threat_hints.",
            ["IEC 62443-3-3 SR 6.2"],
        )

    # Passive exposure index (0–100): weighted finding severities — not CVSS.
    w = {"CRITICAL": 22, "HIGH": 12, "MEDIUM": 6, "LOW": 2, "INFO": 1}
    raw = sum(w.get(f["severity"], 0) for f in findings)
    exposure_index = min(100, raw)

    write_samples = []
    for f in flows:
        if not f.has_write_operations:
            continue
        write_samples.append(
            {
                "src_ip": f.src_ip,
                "dst_ip": f.dst_ip,
                "src_port": f.src_port,
                "dst_port": f.dst_port,
                "transport": f.transport_protocol,
                "ics_protocol": f.ics_protocol,
                "packet_count": f.packet_count,
                "byte_count": f.byte_count,
                "flow_id": f.flow_id,
            },
        )
    write_samples.sort(key=lambda x: x["packet_count"], reverse=True)
    write_samples = write_samples[:80]

    mitre_ids: set[str] = set()
    for f in findings:
        for m in f.get("mitre_attack_references") or []:
            if isinstance(m, dict) and m.get("id"):
                mitre_ids.add(str(m["id"]))

    return {
        "workbook_version": "1.0",
        "scope_statement": (
            "Passive offline PCAP/PCAPNG analysis only — no authentication testing, exploitation, or live interaction. "
            "All conclusions are hypotheses suitable for correlation with architecture documentation, CMDB, and change control."
        ),
        "limitations": [
            "No visibility into serial fieldbuses, air-gapped cells, or encrypted payloads without keys.",
            "Heuristic roles and EKS tags are not asset inventories from the vendor.",
            "Absence of a finding does not prove absence of risk outside the capture window.",
        ],
        "findings": findings,
        "finding_counts_by_severity": {
            s: sum(1 for f in findings if f["severity"] == s)
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        },
        "passive_exposure_index": exposure_index,
        "passive_exposure_note": "Weighted sum of workbook finding severities (cap 100). Not a CVSS score — use for prioritization only.",
        "write_flow_samples": write_samples,
        "external_facing_assets": [
            {
                "ip_address": a.ip_address,
                "role": a.role.value if a.role else "Unknown",
                "risk_score": round(a.risk_score, 2),
                "protocols_seen": sorted(a.protocols_seen),
            }
            for a in sorted(ext_assets, key=lambda x: x.ip_address)
        ],
        "assets_with_remote_admin_ports": [
            {
                "ip_address": a.ip_address,
                "open_ports": sorted(set(a.open_ports or set()) & risk_admin_ports),
                "role": a.role.value if a.role else "Unknown",
            }
            for a in sorted(admin_hosts, key=lambda x: x.ip_address)
        ],
        "mitre_techniques_referenced": sorted(mitre_ids),
        "pentest_cross_reference": {
            "summary_counts": pentest.get("summary_counts"),
            "high_value_targets": pentest.get("high_value_targets"),
        },
        "threat_pattern_summary": sct,
    }
