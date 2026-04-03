"""Protocol heuristics — port- and payload-based passive guesses."""

from __future__ import annotations

import struct
from typing import Callable, Optional

from luva.core.config import DEFAULT_PORT_PROTOCOL_MAP


def detect_protocol_by_port(src_port: int, dst_port: int) -> Optional[str]:
    """Guess protocol from well-known ports (dst first, then src)."""
    if dst_port in DEFAULT_PORT_PROTOCOL_MAP:
        return DEFAULT_PORT_PROTOCOL_MAP[dst_port]
    if src_port in DEFAULT_PORT_PROTOCOL_MAP:
        return DEFAULT_PORT_PROTOCOL_MAP[src_port]
    return None


def detect_modbus_payload(payload: bytes) -> bool:
    """Heuristic Modbus TCP MBAP (transaction, protocol id 0, length, unit)."""
    if len(payload) < 7:
        return False

    try:
        _, protocol_id, length, _ = struct.unpack(">HHHB", payload[:7])
        if protocol_id != 0:
            return False
        if not (1 <= length <= 253):
            return False
        return True
    except struct.error:
        return False


def detect_s7_payload(payload: bytes) -> bool:
    """Heuristic TPKT header (version 3, reserved 0, length)."""
    if len(payload) < 4:
        return False

    try:
        version, reserved, length = struct.unpack(">BBH", payload[:4])
        if version != 0x03 or reserved != 0x00:
            return False
        if length < 7:
            return False
        return True
    except struct.error:
        return False


def detect_dnp3_payload(payload: bytes) -> bool:
    """Heuristic DNP3 data link start 0x05 0x64."""
    if len(payload) < 3:
        return False

    return payload[0] == 0x05 and payload[1] == 0x64


def detect_enip_payload(payload: bytes) -> bool:
    """Heuristic EtherNet/IP encapsulation command field."""
    if len(payload) < 24:
        return False

    try:
        command = struct.unpack("<H", payload[:2])[0]
        valid_commands = {
            0x0001,  # ListServices
            0x0004,  # ListInterfaces
            0x0063,  # ListIdentity
            0x0065,  # RegisterSession
            0x0066,  # UnregisterSession
            0x006F,  # SendRRData
            0x0070,  # SendUnitData
        }
        return command in valid_commands
    except struct.error:
        return False


def detect_iec104_payload(payload: bytes) -> bool:
    """Heuristic IEC 104 APCI start 0x68."""
    if len(payload) < 2:
        return False

    return payload[0] == 0x68


def detect_opcua_payload(payload: bytes) -> bool:
    """Heuristic OPC UA binary message type prefix (HEL, ACK, OPN, MSG, CLO, ERR)."""
    if len(payload) < 8:
        return False

    try:
        msg_type = payload[:3].decode("ascii")
        return msg_type in ("HEL", "ACK", "OPN", "MSG", "CLO", "ERR")
    except (UnicodeDecodeError, ValueError):
        return False


def detect_bacnet_payload(payload: bytes) -> bool:
    """Heuristic BACnet/IP BVLC type octet 0x81 (ASHRAE 135 Annex J)."""
    return len(payload) >= 4 and payload[0] == 0x81


def detect_mqtt_payload(payload: bytes) -> bool:
    """Heuristic MQTT 3.1.1+ fixed header: message type 1-15 and valid remaining length."""
    if len(payload) < 2:
        return False
    msg_type = (payload[0] >> 4) & 0x0F
    if msg_type < 1 or msg_type > 15:
        return False
    multiplier = 1
    value = 0
    pos = 1
    while pos < len(payload) and pos < 6:
        b = payload[pos]
        pos += 1
        value += (b & 0x7F) * multiplier
        multiplier *= 128
        if multiplier > 128**4:
            return False
        if (b & 0x80) == 0:
            return pos <= len(payload) and pos + value <= len(payload)
    return False


def detect_snmp_payload(payload: bytes) -> bool:
    """Heuristic SNMP: BER SEQUENCE with a version integer 0..3 (v1/v2c/v3 envelope)."""
    from luva.parsers.snmp import _parse_snmp_v1v2c_pdu_type

    _, _, meta = _parse_snmp_v1v2c_pdu_type(payload)
    return meta.get("snmp_version") is not None


PAYLOAD_DETECTORS: dict[str, Callable[[bytes], bool]] = {
    "modbus": detect_modbus_payload,
    "s7": detect_s7_payload,
    "dnp3": detect_dnp3_payload,
    "enip": detect_enip_payload,
    "iec104": detect_iec104_payload,
    "opcua": detect_opcua_payload,
    "bacnet": detect_bacnet_payload,
    "mqtt": detect_mqtt_payload,
    "snmp": detect_snmp_payload,
}


def detect_protocol_by_payload(payload: bytes, candidate_protocols: list[str] | None = None) -> Optional[str]:
    """Return first slug in candidate list that matches payload shape.

    Args:
        payload: Raw L7 bytes.
        candidate_protocols: Slugs to try; default all registered detectors.

    Returns:
        Matched slug or None.
    """
    protocols_to_check = candidate_protocols or list(PAYLOAD_DETECTORS.keys())

    for proto in protocols_to_check:
        detector = PAYLOAD_DETECTORS.get(proto)
        if detector and detector(payload):
            return proto

    return None
