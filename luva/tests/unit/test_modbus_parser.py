"""Unit tests for Modbus TCP parser."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.modbus import ModbusParser


def _mbap(transaction_id: int, length: int, unit_id: int) -> bytes:
    return struct.pack(">HHHB", transaction_id, 0, length, unit_id)


def _packet(
    payload: bytes,
    *,
    src_port: int = 50000,
    dst_port: int = 502,
) -> PacketMetadata:
    return PacketMetadata(
        packet_number=1,
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        length=len(payload) + 40,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=src_port,
        dst_port=dst_port,
        transport="TCP",
        payload=payload,
        payload_length=len(payload),
    )


def test_parse_read_holding_registers_request() -> None:
    """FC 0x03 request extracts starting address and quantity."""
    pdu = struct.pack(">BHH", 0x03, 100, 10)
    length = 1 + len(pdu)
    payload = _mbap(1, length, 1) + pdu
    pkt = _packet(payload)

    parser = ModbusParser()
    assert parser.can_parse(pkt) is True
    frame = parser.parse(pkt)
    assert frame is not None
    assert frame.protocol == "Modbus"
    assert frame.protocol_slug == "modbus"
    assert frame.function_code == 0x03
    assert frame.payload.get("unit_id") == 1
    assert frame.payload.get("starting_address") == 100
    assert frame.payload.get("quantity") == 10
    assert frame.is_request is True


def test_parse_exception_response() -> None:
    """Exception response sets is_exception and exception code."""
    pdu = bytes([0x83, 0x02])
    length = 1 + len(pdu)
    payload = _mbap(2, length, 1) + pdu
    pkt = _packet(payload, src_port=502, dst_port=50000)

    frame = ModbusParser().parse(pkt)
    assert frame is not None
    assert frame.is_exception is True
    assert frame.payload.get("exception_code") == 0x02
    assert frame.message_type == "exception"


def test_broadcast_write_rule_payload() -> None:
    """Unit ID 255 with write FC is parseable for rule matching."""
    pdu = struct.pack(">BHH", 0x06, 0, 1)
    length = 1 + len(pdu)
    payload = _mbap(3, length, 255) + pdu
    pkt = _packet(payload)

    frame = ModbusParser().parse(pkt)
    assert frame is not None
    assert frame.payload.get("unit_id") == 255
    assert frame.function_code == 0x06
