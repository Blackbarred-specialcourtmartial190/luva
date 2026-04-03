"""Siemens S7 parser — TPKT / COTP / S7 PDU."""

from __future__ import annotations

import struct
import logging
from typing import Optional

from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.base import BaseParser, ProtocolFrame

logger = logging.getLogger(__name__)


class S7Parser(BaseParser):
    """S7comm over TCP: TPKT → COTP → S7 PDU."""

    PROTOCOL_NAME = "S7"
    PROTOCOL_SLUG = "s7"
    DEFAULT_PORTS = [102]
    PAYLOAD_HEURISTIC = True

    # S7 PDU Tipleri
    PDU_TYPES = {
        0x01: "JOB (Request)",
        0x02: "ACK (Acknowledge)",
        0x03: "ACK_DATA (Data Response)",
        0x07: "USERDATA (Diagnostic/System)",
    }

    # S7 function / service codes
    FUNCTION_CODES = {
        0x00: "CPU Services",
        0x04: "Read Variable",
        0x05: "Write Variable",
        0x1A: "Request Download",
        0x1B: "Download Block",
        0x1C: "Download Ended",
        0x1D: "End Download",
        0x1E: "Start Upload",
        0x1F: "Upload",
        0x20: "End Upload",
        0x28: "PLC Control (Start/Stop)",
        0x29: "PLC Stop",
        0xF0: "Setup Communication",
    }

    WRITE_FUNCTION_CODES = {0x05}
    DIAGNOSTIC_FUNCTION_CODES = {0x00}
    CONTROL_FUNCTION_CODES = {0x1A, 0x1B, 0x1C, 0x1D, 0x28, 0x29, 0x1E, 0x1F, 0x20}

    # S7 error classes
    ERROR_CLASSES = {
        0x00: "No error",
        0x81: "Application relationship error",
        0x82: "Object definition error",
        0x83: "No resources available error",
        0x84: "Error on service processing",
        0x85: "Error on supplies",
        0x87: "Access error",
    }

    # COTP PDU Tipleri
    COTP_TYPES = {
        0x0D: "COTP CR (Connect Request)",
        0x0C: "COTP CC (Connect Confirm)",
        0x0F: "COTP DT (Data Transfer)",
        0x08: "COTP DR (Disconnect Request)",
        0x06: "COTP DC (Disconnect Confirm)",
    }

    def can_parse(self, packet: PacketMetadata) -> bool:
        """Port 102 + TPKT heuristic."""
        # Port
        if packet.src_port in self.DEFAULT_PORTS or packet.dst_port in self.DEFAULT_PORTS:
            return True

        # TPKT heuristic
        if packet.payload and len(packet.payload) >= 4:
            try:
                version, reserved = struct.unpack(">BB", packet.payload[:2])
                if version == 0x03 and reserved == 0x00:
                    return True
            except struct.error:
                pass

        return False

    def parse(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        """Parse TPKT → COTP → S7."""
        if not packet.payload or len(packet.payload) < 7:
            return None

        try:
            return self._parse_tpkt(packet)
        except Exception as e:
            logger.debug("S7 parse error (packet #%s): %s", packet.packet_number, e)
            return None

    def _parse_tpkt(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        """TPKT header."""
        data = packet.payload

        # TPKT Header (4 byte)
        version, reserved, tpkt_length = struct.unpack(">BBH", data[:4])

        if version != 0x03 or reserved != 0x00:
            return None

        payload_dict = {
            "tpkt_version": version,
            "tpkt_length": tpkt_length,
        }

        # COTP Header (data[4:])
        if len(data) < 5:
            return None

        return self._parse_cotp(packet, data[4:], payload_dict)

    def _parse_cotp(self, packet: PacketMetadata, data: bytes, payload: dict) -> Optional[ProtocolFrame]:
        """COTP header."""
        if len(data) < 2:
            return None

        cotp_length = data[0]
        cotp_pdu_type = data[1] >> 4  # high nibble

        cotp_full_type = data[1]
        payload["cotp_length"] = cotp_length
        payload["cotp_pdu_type"] = cotp_full_type
        payload["cotp_pdu_type_name"] = self.COTP_TYPES.get(
            cotp_full_type, f"Unknown COTP (0x{cotp_full_type:02X})"
        )

        # COTP connect: no S7 PDU yet
        if cotp_full_type in (0x0D, 0x0C):
            return self._build_frame(
                packet=packet,
                function_code=None,
                payload=payload,
                is_request=(cotp_full_type == 0x0D),
                message_type="cotp_connection",
            )

        # COTP DT (0x0F): S7 PDU follows
        if cotp_pdu_type == 0x0F or cotp_full_type == 0xF0:
            s7_offset = 1 + cotp_length
            if len(data) > s7_offset:
                return self._parse_s7_pdu(packet, data[s7_offset:], payload)

        # Other COTP PDU types
        return self._build_frame(
            packet=packet,
            function_code=None,
            payload=payload,
            message_type="cotp_other",
        )

    def _parse_s7_pdu(self, packet: PacketMetadata, data: bytes, payload: dict) -> Optional[ProtocolFrame]:
        """S7 PDU."""
        if len(data) < 10:
            return None

        # S7 Header
        protocol_id = data[0]  # expect 0x32
        if protocol_id != 0x32:
            return None

        pdu_type = data[1]
        pdu_reference = struct.unpack(">H", data[4:6])[0]
        param_length = struct.unpack(">H", data[6:8])[0]
        data_length = struct.unpack(">H", data[8:10])[0]

        payload["s7_protocol_id"] = protocol_id
        payload["s7_pdu_type"] = pdu_type
        payload["s7_pdu_type_name"] = self.PDU_TYPES.get(pdu_type, f"Unknown (0x{pdu_type:02X})")
        payload["s7_pdu_reference"] = pdu_reference
        payload["s7_param_length"] = param_length
        payload["s7_data_length"] = data_length

        # Hata kodu (ACK ve ACK_DATA'da var)
        error_class = 0
        error_code = 0
        if pdu_type in (0x02, 0x03) and len(data) >= 12:
            error_class = data[10]
            error_code = data[11]
            payload["s7_error_class"] = error_class
            payload["s7_error_class_name"] = self.ERROR_CLASSES.get(
                error_class, f"Unknown (0x{error_class:02X})"
            )
            payload["s7_error_code"] = error_code

        # Parametre verisi
        param_offset = 12 if pdu_type in (0x02, 0x03) else 10
        if param_length > 0 and len(data) > param_offset:
            param_data = data[param_offset:param_offset + param_length]
            if len(param_data) > 0:
                function_code = param_data[0]
                payload["s7_function_code"] = function_code
                payload["s7_function_name"] = self.FUNCTION_CODES.get(
                    function_code, f"Unknown (0x{function_code:02X})"
                )

                # Per-function parse
                self._parse_s7_function(function_code, param_data[1:], payload)

                is_request = pdu_type == 0x01
                is_exception = error_class != 0

                return self._build_frame(
                    packet=packet,
                    function_code=function_code,
                    payload=payload,
                    is_request=is_request,
                    is_exception=is_exception,
                    message_type=self.PDU_TYPES.get(pdu_type, "unknown"),
                )

        # Fonksiyon kodu olmadan genel frame
        return self._build_frame(
            packet=packet,
            function_code=None,
            payload=payload,
            is_request=(pdu_type == 0x01),
            message_type=self.PDU_TYPES.get(pdu_type, "unknown"),
        )

    def _parse_s7_function(self, fc: int, data: bytes, payload: dict) -> None:
        """Function-specific payload fields."""
        match fc:
            case 0xF0:
                # Setup Communication
                if len(data) >= 6:
                    _, max_amq_calling, max_amq_called, pdu_size = struct.unpack(">BHHH", data[:7]) if len(data) >= 7 else (0, 0, 0, 0)
                    if len(data) >= 7:
                        payload["max_amq_calling"] = max_amq_calling
                        payload["max_amq_called"] = max_amq_called
                        payload["pdu_size"] = pdu_size

            case 0x04 | 0x05:
                # Read/write var: item count
                if len(data) >= 1:
                    item_count = data[0]
                    payload["item_count"] = item_count

            case 0x28 | 0x29:
                # PLC Control / PLC Stop
                payload["control_action"] = "START" if fc == 0x28 else "STOP"

            case 0x1A | 0x1B:
                # Download (program transfer)
                payload["download_action"] = "request" if fc == 0x1A else "transfer"
