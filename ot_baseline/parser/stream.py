"""
Streaming PCAP reader built on Scapy — bounded memory, IPv4/IPv6, L4 metadata.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from scapy.all import ICMP, IP, PcapReader, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from ot_baseline.parser.records import PacketRecord

logger = logging.getLogger(__name__)

# Cap stored TCP payload per packet so huge transfers do not blow RAM
DEFAULT_MAX_PAYLOAD = 4096


def _ip_layer(pkt: Packet) -> tuple[object | None, int]:
    """Return (ip_layer, version) or (None, 0)."""
    if IP in pkt:
        return pkt[IP], 4
    if IPv6 in pkt:
        return pkt[IPv6], 6
    return None, 0


def _packet_to_record(pkt: Packet, max_payload: int) -> PacketRecord | None:
    ip, ver = _ip_layer(pkt)
    if ip is None:
        return None
    ts = float(pkt.time)
    src_ip = ip.src
    dst_ip = ip.dst
    if IP in pkt:
        length = int(ip.len) if getattr(ip, "len", None) is not None else len(pkt)
    elif IPv6 in pkt:
        plen = getattr(ip, "plen", None)
        length = 40 + int(plen) if plen is not None else len(pkt)
    else:
        length = len(pkt)

    sport: int | None = None
    dport: int | None = None
    proto_name = "other"
    ip_proto_num = int(ip.proto) if ip.proto is not None else -1
    payload = b""
    raw_len = 0

    if TCP in pkt:
        tcp = pkt[TCP]
        sport = int(tcp.sport)
        dport = int(tcp.dport)
        proto_name = "tcp"
        if tcp.payload:
            raw = bytes(tcp.payload)
            raw_len = len(raw)
            payload = raw[:max_payload]
    elif UDP in pkt:
        udp = pkt[UDP]
        sport = int(udp.sport)
        dport = int(udp.dport)
        proto_name = "udp"
        if udp.payload:
            raw = bytes(udp.payload)
            raw_len = len(raw)
            payload = raw[:max_payload]
    elif ICMP in pkt:
        proto_name = "icmp"

    return PacketRecord(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_version=ver,
        proto=proto_name,
        ip_proto_num=ip_proto_num,
        length=length,
        sport=sport,
        dport=dport,
        tcp_payload=payload,
        raw_l4_payload_len=raw_len,
    )


def iter_packet_records(
    pcap_path: Path,
    *,
    max_payload_capture: int = DEFAULT_MAX_PAYLOAD,
) -> Iterator[PacketRecord]:
    """
    Stream ``pcap_path`` and yield :class:`PacketRecord` for each IPv4/IPv6 packet.

    Non-IP frames are skipped. Uses Scapy's :class:`PcapReader` (iterator, not load).
    """
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP not found: {path}")

    count = 0
    errors = 0
    try:
        reader = PcapReader(str(path))
    except Exception as exc:
        logger.exception("Failed to open PCAP: %s", path)
        raise RuntimeError(f"Cannot open PCAP {path}: {exc}") from exc

    try:
        for pkt in reader:
            count += 1
            try:
                rec = _packet_to_record(pkt, max_payload_capture)
                if rec is not None:
                    yield rec
            except Exception as exc:
                errors += 1
                if errors <= 5:
                    logger.warning("Decode error at packet ~%s: %s", count, exc)
    finally:
        try:
            reader.close()
        except Exception:
            pass

    if errors:
        logger.info("Completed %s IP packets (%s decode warnings/errors).", count, errors)
