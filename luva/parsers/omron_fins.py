"""Omron FINS — minimal passive framing over TCP/UDP (port 9600)."""

from __future__ import annotations

import logging
import struct
from typing import Optional

from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.base import BaseParser, ProtocolFrame

logger = logging.getLogger(__name__)


class OmronFinsParser(BaseParser):
    """FINS command/response hints on well-known Omron ports (not a full protocol state machine)."""

    PROTOCOL_NAME = "Omron FINS"
    PROTOCOL_SLUG = "omron_fins"
    DEFAULT_PORTS = [9600]
    PAYLOAD_HEURISTIC = True

    FUNCTION_CODES: dict[int, str] = {
        0x0101: "Memory Area Read",
        0x0102: "Memory Area Write",
        0x0103: "Memory Area Fill",
        0x0104: "Multiple Memory Area Read",
        0x0220: "Program Read",
        0x0221: "Program Write",
    }

    WRITE_FUNCTION_CODES = {0x0102, 0x0103, 0x0221}
    DIAGNOSTIC_FUNCTION_CODES: set[int] = set()
    CONTROL_FUNCTION_CODES: set[int] = set()

    def can_parse(self, packet: PacketMetadata) -> bool:
        if packet.transport not in ("TCP", "UDP"):
            return False
        if packet.src_port in self.DEFAULT_PORTS or packet.dst_port in self.DEFAULT_PORTS:
            return True
        if packet.payload and len(packet.payload) >= 12:
            return self._looks_like_fins_header(packet.payload)
        return False

    def _looks_like_fins_header(self, data: bytes) -> bool:
        """ICF + reserved + gateway count + addressing bytes (heuristic)."""
        if len(data) < 10:
            return False
        icf, _rsv, gct = data[0], data[1], data[2]
        if gct > 8:
            return False
        # ICF response bit and common routing lengths
        return icf in (0x80, 0x81, 0x82, 0x83, 0x00, 0x01, 0x02, 0x03)

    def parse(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        if not packet.payload or len(packet.payload) < 8:
            return None
        data = packet.payload
        try:
            icf = data[0]
            gct = data[2]
            cmd_offset = 10 + max(0, min(gct, 7)) * 2
            if len(data) < cmd_offset + 2:
                return self._build_frame(
                    packet,
                    function_code=None,
                    payload={"fins_icf": icf, "fins_note": "short FINS frame"},
                    message_type="fins_partial",
                )
            mrc, src = data[cmd_offset], data[cmd_offset + 1]
            cmd_word = (mrc << 8) | src
            name = self.FUNCTION_CODES.get(cmd_word, f"FINS 0x{mrc:02X}{src:02X}")
            frame = self._build_frame(
                packet,
                function_code=cmd_word,
                payload={
                    "fins_icf": icf,
                    "fins_mrc": mrc,
                    "fins_src": src,
                    "fins_command_word": cmd_word,
                },
                is_request=(icf & 0x80) == 0,
                message_type=name,
            )
            if frame.is_write_operation:
                frame.risk_note = "FINS write — verify authorized engineering access"
            return frame
        except (IndexError, struct.error) as e:
            logger.debug("FINS parse error #%s: %s", packet.packet_number, e)
            return None
