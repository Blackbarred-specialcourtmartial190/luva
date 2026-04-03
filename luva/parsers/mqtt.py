"""MQTT (ISO/IEC 20922) — fixed header and type for passive OT/IIoT broker visibility."""

from __future__ import annotations

import logging
from typing import Optional

from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.base import BaseParser, ProtocolFrame

logger = logging.getLogger(__name__)

MQTT_TYPES: dict[int, str] = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH",
}


def _mqtt_remaining_length(data: bytes, start: int) -> tuple[int, int]:
    """Return (value, bytes_consumed) for MQTT variable-length integer."""
    multiplier = 1
    value = 0
    pos = start
    while pos < len(data) and pos < start + 5:
        b = data[pos]
        pos += 1
        value += (b & 0x7F) * multiplier
        multiplier *= 128
        if multiplier > 128 * 128 * 128 * 128:
            break
        if (b & 0x80) == 0:
            return value, pos - start
    return 0, 0


class MQTTParser(BaseParser):
    """MQTT 3.1.1 / 5.0 style fixed header (best-effort)."""

    PROTOCOL_NAME = "MQTT"
    PROTOCOL_SLUG = "mqtt"
    DEFAULT_PORTS = [1883, 8883, 8884, 9001]

    FUNCTION_CODES = MQTT_TYPES

    WRITE_FUNCTION_CODES = {3, 8, 10}  # PUBLISH, SUBSCRIBE, UNSUBSCRIBE
    DIAGNOSTIC_FUNCTION_CODES = {1, 2, 12, 13, 14, 15}  # connect/session/ping/auth
    CONTROL_FUNCTION_CODES = set()

    def can_parse(self, packet: PacketMetadata) -> bool:
        if packet.transport != "TCP":
            return False
        if packet.src_port in self.DEFAULT_PORTS or packet.dst_port in self.DEFAULT_PORTS:
            return True
        return False

    def parse(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        if not packet.payload or len(packet.payload) < 2:
            return None
        try:
            return self._parse_mqtt(packet)
        except Exception as e:
            logger.debug("MQTT parse error (packet #%s): %s", packet.packet_number, e)
            return None

    def _parse_mqtt(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        data = packet.payload
        first = data[0]
        msg_type = (first >> 4) & 0x0F
        flags = first & 0x0F
        if msg_type < 1 or msg_type > 15:
            return None
        rem, consumed = _mqtt_remaining_length(data, 1)
        if consumed == 0:
            return None
        if 1 + consumed > len(data) or 1 + consumed + rem > len(data):
            return None

        name = MQTT_TYPES.get(msg_type, f"MQTT-{msg_type}")
        payload: dict = {
            "mqtt_message_type": msg_type,
            "mqtt_flags": flags,
            "remaining_length": rem,
        }

        pos = 1 + consumed
        if msg_type == 3 and pos + 2 <= len(data):
            topic_len = int.from_bytes(data[pos : pos + 2], "big")
            pos += 2
            if 0 < topic_len < 4096 and pos + topic_len <= len(data):
                payload["topic"] = data[pos : pos + topic_len].decode("utf-8", errors="replace")

        frame = self._build_frame(
            packet,
            function_code=msg_type,
            payload=payload,
            is_request=msg_type in (1, 3, 8, 10, 12, 14, 15),
            message_type=name,
        )
        frame.function_name = name
        return frame
