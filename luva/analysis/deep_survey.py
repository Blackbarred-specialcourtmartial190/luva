"""Passive deep packet survey — transport, ports, DNS, TLS hints, cleartext fingerprints."""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from typing import Any, Optional

from scapy.layers.dns import DNS

from luva.analysis.cleartext_ot_sensitive import inspect_tcp_ot_cleartext, inspect_udp_ot_cleartext
from luva.engine.pcap_reader import PacketMetadata
from luva.utils.ip_utils import is_private_ipv4, is_public_ipv4
from luva.utils.port_registry import ICS_PORT_REGISTRY, lookup_port

_IP_PROTO_NAMES: dict[int, str] = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}

_MAX_DNS_PARSE = 500_000
_MAX_UNIQUE_DNS_NAMES = 12_000
_MAX_HOST_STRINGS = 200
_MAX_UNIQUE_HTTP_HOSTS = 12_000
_HTTP_HOST_RE = re.compile(rb"Host:\s*([^\r\n]+)", re.I)
_TLS_RECORD = re.compile(rb"^\x16[\x03][\x01\x02\x03\x04]")

_MAX_OT_SENSITIVE_SAMPLES = 40
_MAX_TCP_PAYLOAD_FP_KEYS = 80_000
_MAX_CREDENTIAL_HINT_SAMPLES = 24


class DeepPacketSurvey:
    """Accumulate per-packet statistics suitable for security assessment reports."""

    def __init__(self) -> None:
        self._first_ts: Optional[float] = None
        self._last_ts: Optional[float] = None
        self.total_l2_only: int = 0
        self.total_with_ip: int = 0

        self.ip_proto_counts: Counter[int] = Counter()
        self.ethertype_counts: Counter[int] = Counter()

        self.tcp_syn_only: int = 0
        self.tcp_rst: int = 0
        self.tcp_fin: int = 0
        self.tcp_with_payload: int = 0

        self.dst_tcp_ports: Counter[int] = Counter()
        self.src_tcp_ports: Counter[int] = Counter()
        self.dst_udp_ports: Counter[int] = Counter()
        self.src_udp_ports: Counter[int] = Counter()

        self.unique_src_ips: set[str] = set()
        self.unique_dst_ips: set[str] = set()
        self.unique_src_macs: set[str] = set()
        self.unique_dst_macs: set[str] = set()

        self.src_private: int = 0
        self.src_public: int = 0
        self.dst_private: int = 0
        self.dst_public: int = 0

        self._packets_per_minute: Counter[int] = Counter()

        self.dns_queries: Counter[str] = Counter()
        self._dns_parsed: int = 0

        self.tls_handshake_guess: int = 0
        self.tls_ports: Counter[int] = Counter()

        self.http_hosts: Counter[str] = Counter()
        self._http_extracts: int = 0

        self.cleartext_hints: Counter[str] = Counter()
        self._banner_samples: list[dict[str, str]] = []

        self.ics_port_hits: Counter[tuple[str, int, str]] = Counter()  # (side, port, label)

        self._ot_sensitive_hits: Counter[str] = Counter()
        self._ot_sensitive_samples: list[dict[str, Any]] = []
        self._ot_sensitive_keys: set[tuple[Any, ...]] = set()

        self._arp_frames = 0
        self._ipv4_broadcast = 0
        self._scanner_hits: Counter[str] = Counter()
        self._cred_samples: list[dict[str, str]] = []
        self._tcp_payload_fp: Counter[str] = Counter()

    def process(self, meta: PacketMetadata) -> None:
        ts = meta.timestamp.timestamp()
        if self._first_ts is None:
            self._first_ts = ts
        self._last_ts = ts
        self._packets_per_minute[int(ts // 60)] += 1

        if meta.src_mac:
            self.unique_src_macs.add(meta.src_mac)
        if meta.dst_mac:
            self.unique_dst_macs.add(meta.dst_mac)
        if meta.eth_type is not None:
            self.ethertype_counts[meta.eth_type] += 1
        if meta.eth_type == 0x0806:
            self._arp_frames += 1

        if not meta.src_ip or not meta.dst_ip:
            self.total_l2_only += 1
            return

        self.total_with_ip += 1
        self.unique_src_ips.add(meta.src_ip)
        self.unique_dst_ips.add(meta.dst_ip)
        if meta.dst_ip == "255.255.255.255":
            self._ipv4_broadcast += 1

        if is_private_ipv4(meta.src_ip):
            self.src_private += 1
        elif is_public_ipv4(meta.src_ip):
            self.src_public += 1
        if is_private_ipv4(meta.dst_ip):
            self.dst_private += 1
        elif is_public_ipv4(meta.dst_ip):
            self.dst_public += 1

        if meta.ip_proto is not None:
            self.ip_proto_counts[meta.ip_proto] += 1

        if meta.transport == "TCP" and meta.src_port and meta.dst_port:
            self.src_tcp_ports[meta.src_port] += 1
            self.dst_tcp_ports[meta.dst_port] += 1
            flags = meta.tcp_flags or ""
            if "R" in flags:
                self.tcp_rst += 1
            if "F" in flags:
                self.tcp_fin += 1
            if "S" in flags and "A" not in flags:
                self.tcp_syn_only += 1
            if meta.payload_length > 0:
                self.tcp_with_payload += 1
            self._inspect_tcp_payload(meta)
            info = lookup_port(meta.dst_port)
            if info and info.is_ics and info.transport in ("tcp", "both"):
                self.ics_port_hits[("dst_tcp", meta.dst_port, info.service_name)] += 1
            info_s = lookup_port(meta.src_port)
            if info_s and info_s.is_ics and info_s.transport in ("tcp", "both"):
                self.ics_port_hits[("src_tcp", meta.src_port, info_s.service_name)] += 1

        elif meta.transport == "UDP" and meta.src_port and meta.dst_port:
            self.src_udp_ports[meta.src_port] += 1
            self.dst_udp_ports[meta.dst_port] += 1
            self._inspect_udp_payload(meta)
            info = lookup_port(meta.dst_port)
            if info and info.is_ics and info.transport in ("udp", "both"):
                self.ics_port_hits[("dst_udp", meta.dst_port, info.service_name)] += 1
            info_s = lookup_port(meta.src_port)
            if info_s and info_s.is_ics and info_s.transport in ("udp", "both"):
                self.ics_port_hits[("src_udp", meta.src_port, info_s.service_name)] += 1

    def _inspect_tcp_payload(self, meta: PacketMetadata) -> None:
        pl = meta.payload
        if not pl or len(pl) < 4:
            return
        if _TLS_RECORD.match(pl[:4]):
            self.tls_handshake_guess += 1
            if meta.dst_port is not None:
                self.tls_ports[meta.dst_port] += 1
        if pl.startswith(b"SSH-2.0") or pl.startswith(b"SSH-1.99"):
            self.cleartext_hints["ssh_banner"] += 1
            self._push_banner("SSH", pl[:120])
        elif pl.startswith(b"220 ") and (b"FTP" in pl[:80] or b"ftp" in pl[:80].lower()):
            self.cleartext_hints["ftp_banner"] += 1
            self._push_banner("FTP", pl[:120])
        elif meta.dst_port == 23 or meta.src_port == 23:
            self.cleartext_hints["telnet_port"] += 1
        if pl.startswith(b"GET ") or pl.startswith(b"POST ") or pl.startswith(b"HTTP/"):
            self.cleartext_hints["http_like"] += 1
            m = _HTTP_HOST_RE.search(pl[:2048])
            if m and self._http_extracts < _MAX_HOST_STRINGS:
                try:
                    host = m.group(1).decode("utf-8", errors="replace").strip()[:255]
                    if host:
                        if host not in self.http_hosts and len(self.http_hosts) >= _MAX_UNIQUE_HTTP_HOSTS:
                            self.http_hosts["<other hosts>"] += 1
                        else:
                            self.http_hosts[host] += 1
                        self._http_extracts += 1
                except Exception:
                    pass

        self._maybe_scanner_tool_strings(pl)
        self._maybe_credential_hints(pl)
        self._maybe_count_tcp_payload_fingerprint(pl)

        for ot_obs in inspect_tcp_ot_cleartext(meta, pl):
            self._record_ot_sensitive(meta, ot_obs)

    def _maybe_scanner_tool_strings(self, pl: bytes) -> None:
        head = pl[:2048]
        markers = (
            b"Nmap",
            b"nmap.org",
            b"Masscan",
            b"masscan",
            b"Nuclei/",
            b"Zmap",
            b"plcscan",
            b"s7-scan",
            b"PLC-Scan",
        )
        for m in markers:
            if m in head:
                key = m.decode("utf-8", errors="replace")[:48]
                self._scanner_hits[key] += 1
                return

    def _maybe_credential_hints(self, pl: bytes) -> None:
        if len(self._cred_samples) >= _MAX_CREDENTIAL_HINT_SAMPLES:
            return
        head = pl[:4096]
        if b"Authorization: Basic " in head:
            idx = head.index(b"Authorization: Basic ")
            excerpt = head[idx : idx + 100].decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ")
            self._cred_samples.append(
                {"type": "http_basic_auth", "credential_hint_excerpt": excerpt[:160]},
            )
            return
        if b"\r\nUSER " in head or head.upper().startswith(b"USER "):
            self._cred_samples.append(
                {
                    "type": "ftp_user_line",
                    "credential_hint_excerpt": "FTP USER command or banner context observed (cleartext)",
                },
            )

    def _maybe_count_tcp_payload_fingerprint(self, pl: bytes) -> None:
        if _TLS_RECORD.match(pl[:4]) or len(pl) < 32 or len(pl) > 1400:
            return
        fp = hashlib.md5(pl[:48]).hexdigest()
        if fp in self._tcp_payload_fp or len(self._tcp_payload_fp) < _MAX_TCP_PAYLOAD_FP_KEYS:
            self._tcp_payload_fp[fp] += 1

    def _inspect_udp_payload(self, meta: PacketMetadata) -> None:
        pl = meta.payload
        if not pl:
            return
        if meta.dst_port == 53 or meta.src_port == 53:
            if self._dns_parsed < _MAX_DNS_PARSE:
                self._try_dns(pl)
        if meta.dst_port == 161 or meta.src_port == 161:
            self.cleartext_hints["snmp_udp"] += 1

        for ot_obs in inspect_udp_ot_cleartext(meta, pl):
            self._record_ot_sensitive(meta, ot_obs)

    def _try_dns(self, pl: bytes) -> None:
        self._dns_parsed += 1
        try:
            d = DNS(pl)
            if d.qd:
                q = d.qd
                name = q.qname.decode(errors="replace").rstrip(".")
                if name:
                    if name not in self.dns_queries and len(self.dns_queries) >= _MAX_UNIQUE_DNS_NAMES:
                        self.dns_queries["<other dns names>"] += 1
                    else:
                        self.dns_queries[name] += 1
        except Exception:
            return

    def _record_ot_sensitive(self, meta: PacketMetadata, obs: dict[str, Any]) -> None:
        cat = str(obs.get("category", "unknown"))
        self._ot_sensitive_hits[cat] += 1
        dedupe = obs.get("dedupe_key", "")
        key = (
            cat,
            meta.src_ip,
            meta.dst_ip,
            meta.dst_port or 0,
            meta.src_port or 0,
            dedupe,
        )
        if key in self._ot_sensitive_keys or len(self._ot_sensitive_samples) >= _MAX_OT_SENSITIVE_SAMPLES:
            return
        self._ot_sensitive_keys.add(key)
        row = {k: v for k, v in obs.items() if k != "dedupe_key"}
        row["src_ip"] = meta.src_ip
        row["dst_ip"] = meta.dst_ip
        row["src_port"] = meta.src_port
        row["dst_port"] = meta.dst_port
        row["transport"] = meta.transport or ""
        self._ot_sensitive_samples.append(row)

    def _push_banner(self, proto: str, snippet: bytes) -> None:
        if len(self._banner_samples) >= 40:
            return
        text = snippet.decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ")[:200]
        self._banner_samples.append({"protocol": proto, "sample": text})

    def _downsample_timeline(self) -> tuple[list[str], list[int]]:
        from datetime import datetime, timezone

        if not self._packets_per_minute:
            return [], []
        min_keys = sorted(self._packets_per_minute.keys())
        max_points = 200
        if len(min_keys) <= max_points:
            labels: list[str] = []
            vals: list[int] = []
            for mk in min_keys:
                t0 = mk * 60
                labels.append(datetime.fromtimestamp(t0, tz=timezone.utc).strftime("%m-%d %H:%M"))
                vals.append(self._packets_per_minute[mk])
            return labels, vals
        bin_w = max(1, (min_keys[-1] - min_keys[0] + 1) // max_points)
        agg: dict[int, int] = defaultdict(int)
        for mk in self._packets_per_minute:
            b = (mk - min_keys[0]) // max(1, bin_w)
            agg[b] += self._packets_per_minute[mk]
        labels2: list[str] = []
        vals2: list[int] = []
        for b in sorted(agg.keys()):
            t0 = (min_keys[0] + b * bin_w) * 60
            labels2.append(datetime.fromtimestamp(t0, tz=timezone.utc).strftime("%m-%d %H:%M"))
            vals2.append(agg[b])
        return labels2, vals2

    def to_dict(self) -> dict[str, Any]:
        span = 0.0
        if self._first_ts is not None and self._last_ts is not None:
            span = max(self._last_ts - self._first_ts, 0.0)
        total = self.total_with_ip + self.total_l2_only
        pps = (total / span) if span > 0 else 0.0

        ip_named = {
            _IP_PROTO_NAMES.get(k, f"proto_{k}"): v for k, v in self.ip_proto_counts.most_common(32)
        }

        def top_ports(c: Counter[int], n: int = 25) -> list[dict[str, Any]]:
            out: list[dict[str, Any]] = []
            for port, cnt in c.most_common(n):
                info = lookup_port(port)
                out.append(
                    {
                        "port": port,
                        "packets": cnt,
                        "service": info.service_name if info else None,
                        "ics": bool(info and info.is_ics),
                        "risk": info.risk_level if info else None,
                    }
                )
            return out

        timeline_labels, timeline_values = self._downsample_timeline()

        ics_exposure: list[dict[str, Any]] = []
        for (side, port, label), cnt in self.ics_port_hits.most_common(40):
            reg = ICS_PORT_REGISTRY.get(port)
            ics_exposure.append(
                {
                    "observation": side,
                    "port": port,
                    "label": label,
                    "packets": cnt,
                    "risk": reg.risk_level if reg else "unknown",
                }
            )

        from datetime import datetime, timezone

        def _iso(ts: Optional[float]) -> Optional[str]:
            if ts is None:
                return None
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

        repeat_fp = [
            {"fingerprint_md5_first_48b": k, "occurrences": v}
            for k, v in self._tcp_payload_fp.most_common(40)
            if v >= 4
        ][:20]

        return {
            "capture_window": {
                "first_packet_utc": _iso(self._first_ts),
                "last_packet_utc": _iso(self._last_ts),
                "span_seconds": round(span, 3),
                "packets_total": total,
                "packets_with_ipv4": self.total_with_ip,
                "non_ip_frames": self.total_l2_only,
                "avg_packets_per_second": round(pps, 3),
            },
            "uniques": {
                "src_ipv4": len(self.unique_src_ips),
                "dst_ipv4": len(self.unique_dst_ips),
                "src_mac": len(self.unique_src_macs),
                "dst_mac": len(self.unique_dst_macs),
            },
            "addressing": {
                "src_private_hits": self.src_private,
                "src_public_hits": self.src_public,
                "dst_private_hits": self.dst_private,
                "dst_public_hits": self.dst_public,
            },
            "ip_protocols": ip_named,
            "ethertypes_top": [
                {"ethertype": hex(et), "count": n}
                for et, n in self.ethertype_counts.most_common(12)
            ],
            "tcp_behavior": {
                "syn_without_ack_segments": self.tcp_syn_only,
                "rst_segments": self.tcp_rst,
                "fin_segments": self.tcp_fin,
                "segments_with_payload": self.tcp_with_payload,
            },
            "top_destination_tcp_ports": top_ports(self.dst_tcp_ports),
            "top_source_tcp_ports": top_ports(self.src_tcp_ports),
            "top_destination_udp_ports": top_ports(self.dst_udp_ports),
            "top_source_udp_ports": top_ports(self.src_udp_ports),
            "dns_qnames_top": [{"name": n, "count": c} for n, c in self.dns_queries.most_common(40)],
            "tls": {
                "likely_client_hello_records": self.tls_handshake_guess,
                "hits_by_tcp_port": [{"port": p, "count": c} for p, c in self.tls_ports.most_common(15)],
            },
            "http_hosts_top": [{"host": h, "count": c} for h, c in self.http_hosts.most_common(40)],
            "cleartext_hints": dict(self.cleartext_hints),
            "cleartext_ot_sensitive": {
                "note": (
                    "Heuristic samples of OT-related cleartext payloads (truncated hex / redacted SNMP). "
                    "TCP segments may be fragmented; confirm in PCAP. Use --mask-payload to redact excerpts in exports."
                ),
                "hits_by_category": dict(self._ot_sensitive_hits),
                "sample_count": len(self._ot_sensitive_samples),
                "samples": list(self._ot_sensitive_samples),
            },
            "banner_samples": list(self._banner_samples),
            "ics_port_visibility": ics_exposure,
            "timeline": {"labels": timeline_labels, "packets": timeline_values},
            "threat_hints": {
                "note": (
                    "Passive hints only: scanner-like strings, cleartext credential patterns, ARP/broadcast volume, "
                    "and repeated TCP payload prefixes (not full reassembly)."
                ),
                "arp_frames_observed": self._arp_frames,
                "ipv4_broadcast_dest_packets": self._ipv4_broadcast,
                "scanner_tool_string_hits": dict(self._scanner_hits),
                "credential_exposure_samples": list(self._cred_samples),
                "repeated_tcp_payload_fingerprints": repeat_fp,
            },
        }
