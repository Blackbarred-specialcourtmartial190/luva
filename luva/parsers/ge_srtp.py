"""GE SRTP (Service Request Transport Protocol) — passive TCP framing on 18245/18246."""

from __future__ import annotations

import logging
import struct
from typing import Optional

from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.base import BaseParser, ProtocolFrame

logger = logging.getLogger(__name__)


class GeSrtpParser(BaseParser):
    """Minimal SRTP message envelope parsing (sequence + service + payload length)."""

    PROTOCOL_NAME = "GE SRTP"
    PROTOCOL_SLUG = "ge_srtp"
    DEFAULT_PORTS = [18245, 18246]
    PAYLOAD_HEURISTIC = False

    FUNCTION_CODES: dict[int, str] = {
        0x00: "Reserved",
        0x01: "Read Sys Info",
        0x04: "Read PLC Data",
        0x05: "Write PLC Data",
        0x07: "Program Upload/Download",
        0x0E: "Modify PLC Configuration",
    }

    WRITE_FUNCTION_CODES = {0x05, 0x07, 0x0E}
    DIAGNOSTIC_FUNCTION_CODES = {0x01}
    CONTROL_FUNCTION_CODES: set[int] = set()

    def can_parse(self, packet: PacketMetadata) -> bool:
        return (
            packet.transport == "TCP"
            and (packet.src_port in self.DEFAULT_PORTS or packet.dst_port in self.DEFAULT_PORTS)
        )

    def parse(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        if not packet.payload or len(packet.payload) < 8:
            return None
        data = packet.payload
        try:
            seq = struct.unpack(">H", data[0:2])[0]
            reserved = data[2:4]
            if reserved != b"\x00\x00":
                return None
            service = data[4]
            flags = data[5]
            plen = struct.unpack(">H", data[6:8])[0]
            svc_name = self.FUNCTION_CODES.get(service, f"SRTP service 0x{service:02X}")
            is_write = service in self.WRITE_FUNCTION_CODES
            frame = self._build_frame(
                packet,
                function_code=service,
                payload={
                    "srtp_sequence": seq,
                    "srtp_service": service,
                    "srtp_flags": flags,
                    "srtp_payload_length": plen,
                },
                is_request=True,
                message_type=svc_name,
            )
            frame.function_name = svc_name
            frame.is_write_operation = is_write
            if is_write:
                frame.risk_note = "SRTP write/program — operational impact risk"
            return frame
        except (struct.error, IndexError) as e:
            logger.debug("SRTP parse error #%s: %s", packet.packet_number, e)
            return None
