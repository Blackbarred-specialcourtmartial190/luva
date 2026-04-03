"""Typed records produced by the PCAP stream parser."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class PacketRecord:
    """
    Normalized per-packet view for analyzers (IPv4/IPv6, L4 hints).

    ``tcp_payload`` is truncated to ``max_payload_capture`` bytes to bound RAM
    while still allowing Modbus MBAP parsing on typical segments.
    """

    ts: float  # epoch seconds (float, from capture timestamp)
    src_ip: str
    dst_ip: str
    ip_version: int
    proto: str  # "tcp", "udp", "icmp", "other"
    ip_proto_num: int  # IPPROTO_TCP=6, UDP=17, ICMP=1, etc.
    length: int  # L3 (IP) length when available, else link-layer estimate
    sport: int | None = None
    dport: int | None = None
    tcp_payload: bytes = field(default_factory=bytes)
    raw_l4_payload_len: int = 0  # full TCP payload length before truncation
