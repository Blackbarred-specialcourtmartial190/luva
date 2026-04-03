"""Smoke tests: each parser can_parse / parse on minimal crafted metadata."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

import pytest

from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.bacnet import BACnetParser
from luva.parsers.dnp3 import DNP3Parser
from luva.parsers.enip import ENIPParser
from luva.parsers.iec104 import IEC104Parser
from luva.parsers.modbus import ModbusParser
from luva.parsers.mqtt import MQTTParser
from luva.parsers.opcua import OPCUAParser
from luva.parsers.s7comm import S7Parser
from luva.parsers.snmp import SNMPParser


def _meta(**kwargs: object) -> PacketMetadata:
    base = dict(
        packet_number=1,
        timestamp=datetime.now(timezone.utc),
        length=100,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=40000,
        dst_port=502,
        transport="TCP",
        payload=b"",
        payload_length=0,
    )
    base.update(kwargs)
    return PacketMetadata(**base)  # type: ignore[arg-type]


def test_modbus_parser_minimal() -> None:
    pdu = struct.pack(">BHH", 0x03, 0, 10)
    payload = struct.pack(">HHHB", 1, 0, 1 + len(pdu), 1) + pdu
    p = _meta(dst_port=502, payload=payload, payload_length=len(payload))
    parser = ModbusParser()
    assert parser.can_parse(p) is True
    frame = parser.parse(p)
    assert frame is not None
    assert frame.protocol_slug == "modbus"


def test_s7_parser_rejects_http_like_payload_on_non_s7_port() -> None:
    # TPKT-like prefix would match heuristic on any port; use non-TPKT payload.
    p = _meta(dst_port=80, payload=b"GET / HTTP/1.0\r\n", payload_length=16)
    assert S7Parser().can_parse(p) is False


def test_dnp3_heuristic() -> None:
    payload = bytes([0x05, 0x64, 0x0A]) + b"\x00" * 20
    p = _meta(dst_port=20000, payload=payload, payload_length=len(payload))
    parser = DNP3Parser()
    assert parser.can_parse(p) is True


def test_iec104_heuristic() -> None:
    payload = bytes([0x68, 0x04, 0x43, 0x00, 0x00, 0x00])
    p = _meta(dst_port=2404, payload=payload, payload_length=len(payload))
    parser = IEC104Parser()
    assert parser.can_parse(p) is True


def test_enip_list_services() -> None:
    cmd = struct.pack("<H", 0x0001) + b"\x00" * 22
    p = _meta(dst_port=44818, payload=cmd, payload_length=len(cmd))
    parser = ENIPParser()
    assert parser.can_parse(p) is True


@pytest.mark.parametrize(
    "prefix",
    [b"HEL", b"OPN", b"MSG"],
)
def test_opcua_message_prefix(prefix: bytes) -> None:
    payload = prefix + b"F" + b"\x00" * 20
    p = _meta(dst_port=4840, payload=payload, payload_length=len(payload))
    parser = OPCUAParser()
    assert parser.can_parse(p) is True


def test_bacnet_bvlc_i_am() -> None:
    # BVLC Original-Unicast-NPDU, minimal NPDU + unconfirmed I-Am
    payload = bytes([0x81, 0x0A, 0x00, 0x07, 0x00, 0x10, 0x00])
    p = _meta(
        transport="UDP",
        dst_port=47808,
        payload=payload,
        payload_length=len(payload),
    )
    parser = BACnetParser()
    assert parser.can_parse(p) is True
    frame = parser.parse(p)
    assert frame is not None
    assert frame.protocol_slug == "bacnet"


def test_mqtt_pingreq() -> None:
    payload = bytes([0xC0, 0x00])
    p = _meta(dst_port=1883, payload=payload, payload_length=len(payload))
    parser = MQTTParser()
    assert parser.can_parse(p) is True
    frame = parser.parse(p)
    assert frame is not None
    assert frame.protocol_slug == "mqtt"


def test_snmp_get_request() -> None:
    payload = bytes.fromhex("301002010104067075626c6963a003020100")
    p = _meta(
        transport="UDP",
        dst_port=161,
        payload=payload,
        payload_length=len(payload),
    )
    parser = SNMPParser()
    assert parser.can_parse(p) is True
    frame = parser.parse(p)
    assert frame is not None
    assert frame.protocol_slug == "snmp"
