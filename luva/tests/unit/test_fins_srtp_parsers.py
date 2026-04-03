"""Omron FINS and GE SRTP minimal parser smoke."""

from __future__ import annotations

from datetime import datetime, timezone

from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.ge_srtp import GeSrtpParser
from luva.parsers.omron_fins import OmronFinsParser


def _base_pkt() -> PacketMetadata:
    return PacketMetadata(
        packet_number=1,
        timestamp=datetime.now(timezone.utc),
        length=64,
        src_ip="192.168.1.1",
        dst_ip="192.168.1.2",
        transport="TCP",
    )


def test_fins_port_9600_parses() -> None:
    p = OmronFinsParser()
    # ICF, RSV, GCT=0, 7-byte address field, MRC/SRC 0101 (memory read)
    body = bytes([0x80, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01])
    pkt = _base_pkt()
    pkt.src_port = 50000
    pkt.dst_port = 9600
    pkt.payload = body
    assert p.can_parse(pkt)
    frame = p.parse(pkt)
    assert frame is not None
    assert frame.protocol_slug == "omron_fins"


def test_srtp_port_18245_parses() -> None:
    p = GeSrtpParser()
    body = bytes([0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x10]) + b"\x00" * 8
    pkt = _base_pkt()
    pkt.src_port = 50000
    pkt.dst_port = 18245
    pkt.payload = body
    assert p.can_parse(pkt)
    frame = p.parse(pkt)
    assert frame is not None
    assert frame.protocol_slug == "ge_srtp"
    assert frame.function_code == 0x04
