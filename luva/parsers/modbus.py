"""Modbus TCP parser — MBAP + PDU."""

from __future__ import annotations

import struct
import logging
from typing import Optional

from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.base import BaseParser, ProtocolFrame

logger = logging.getLogger(__name__)


class ModbusParser(BaseParser):
    """Modbus/TCP: MBAP (7 bytes) + PDU, request/response handling."""

    PROTOCOL_NAME = "Modbus"
    PROTOCOL_SLUG = "modbus"
    DEFAULT_PORTS = [502]
    PAYLOAD_HEURISTIC = True

    FUNCTION_CODES = {
        0x01: "Read Coils",
        0x02: "Read Discrete Inputs",
        0x03: "Read Holding Registers",
        0x04: "Read Input Registers",
        0x05: "Write Single Coil",
        0x06: "Write Single Register",
        0x07: "Read Exception Status",
        0x08: "Diagnostics",
        0x0B: "Get Comm Event Counter",
        0x0C: "Get Comm Event Log",
        0x0F: "Write Multiple Coils",
        0x10: "Write Multiple Registers",
        0x11: "Report Server ID",
        0x14: "Read File Record",
        0x15: "Write File Record",
        0x16: "Mask Write Register",
        0x17: "Read/Write Multiple Registers",
        0x18: "Read FIFO Queue",
        0x2B: "Encapsulated Interface Transport",
    }

    WRITE_FUNCTION_CODES = {0x05, 0x06, 0x0F, 0x10, 0x15, 0x16, 0x17}
    DIAGNOSTIC_FUNCTION_CODES = {0x07, 0x08, 0x0B, 0x0C, 0x11, 0x2B}
    CONTROL_FUNCTION_CODES = set()  # No dedicated PLC control FCs in Modbus TCP here

    # Exception codes
    EXCEPTION_CODES = {
        0x01: "Illegal Function",
        0x02: "Illegal Data Address",
        0x03: "Illegal Data Value",
        0x04: "Server Device Failure",
        0x05: "Acknowledge",
        0x06: "Server Device Busy",
        0x08: "Memory Parity Error",
        0x0A: "Gateway Path Unavailable",
        0x0B: "Gateway Target Failed to Respond",
    }

    def can_parse(self, packet: PacketMetadata) -> bool:
        """Heuristic: port + MBAP shape."""
        # Port check
        if packet.src_port in self.DEFAULT_PORTS or packet.dst_port in self.DEFAULT_PORTS:
            return True

        # MBAP heuristic
        if packet.payload and len(packet.payload) >= 7:
            try:
                _, protocol_id, length, _ = struct.unpack(">HHHB", packet.payload[:7])
                if protocol_id == 0 and 1 <= length <= 253:
                    return True
            except struct.error:
                pass

        return False

    def parse(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        """Parse Modbus/TCP into ProtocolFrame."""
        if not packet.payload or len(packet.payload) < 8:
            return None

        try:
            return self._parse_modbus_tcp(packet)
        except Exception as e:
            logger.debug("Modbus parse error (packet #%s): %s", packet.packet_number, e)
            return None

    def _parse_modbus_tcp(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        """Parse MBAP and PDU."""
        data = packet.payload

        # MBAP Header (7 byte)
        transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", data[:7])

        if protocol_id != 0:
            return None

        # PDU
        function_code = data[7]
        is_exception = bool(function_code & 0x80)
        actual_fc = function_code & 0x7F if is_exception else function_code

        # Request vs response
        is_request = packet.dst_port in self.DEFAULT_PORTS

        payload_dict = {
            "transaction_id": transaction_id,
            "protocol_id": protocol_id,
            "unit_id": unit_id,
            "length": length,
            "function_code_raw": function_code,
        }

        if is_exception:
            # Exception Response
            exception_code = data[8] if len(data) > 8 else 0
            payload_dict.update({
                "is_exception": True,
                "exception_code": exception_code,
                "exception_name": self.EXCEPTION_CODES.get(exception_code, f"Unknown (0x{exception_code:02X})"),
            })
        else:
            # Standard request/response PDU
            self._parse_pdu(actual_fc, data[8:], is_request, payload_dict)

        message_type = "exception" if is_exception else ("request" if is_request else "response")

        frame = self._build_frame(
            packet=packet,
            function_code=actual_fc,
            payload=payload_dict,
            is_request=is_request,
            is_exception=is_exception,
            message_type=message_type,
        )

        return frame

    def _parse_pdu(self, fc: int, data: bytes, is_request: bool, payload: dict) -> None:
        """PDU body by function code."""
        if len(data) < 2:
            return

        match fc:
            case 0x01 | 0x02 | 0x03 | 0x04:
                # Okuma istekleri
                if is_request and len(data) >= 4:
                    addr, quantity = struct.unpack(">HH", data[:4])
                    payload["starting_address"] = addr
                    payload["quantity"] = quantity
                elif not is_request:
                    byte_count = data[0]
                    payload["byte_count"] = byte_count
                    payload["register_values"] = list(data[1:1 + byte_count])

            case 0x05:
                # Write Single Coil
                if len(data) >= 4:
                    addr, value = struct.unpack(">HH", data[:4])
                    payload["coil_address"] = addr
                    payload["coil_value"] = value
                    payload["coil_state"] = "ON" if value == 0xFF00 else "OFF"

            case 0x06:
                # Write Single Register
                if len(data) >= 4:
                    addr, value = struct.unpack(">HH", data[:4])
                    payload["register_address"] = addr
                    payload["register_value"] = value

            case 0x0F:
                # Write Multiple Coils
                if is_request and len(data) >= 5:
                    addr, quantity = struct.unpack(">HH", data[:4])
                    byte_count = data[4]
                    payload["starting_address"] = addr
                    payload["quantity"] = quantity
                    payload["byte_count"] = byte_count

            case 0x10:
                # Write Multiple Registers
                if is_request and len(data) >= 5:
                    addr, quantity = struct.unpack(">HH", data[:4])
                    byte_count = data[4]
                    payload["starting_address"] = addr
                    payload["quantity"] = quantity
                    payload["byte_count"] = byte_count
                    # Read register values
                    values = []
                    offset = 5
                    for _ in range(quantity):
                        if offset + 2 <= len(data):
                            val = struct.unpack(">H", data[offset:offset + 2])[0]
                            values.append(val)
                            offset += 2
                    payload["register_values"] = values

            case 0x17:
                # Read/Write Multiple Registers
                if is_request and len(data) >= 9:
                    r_addr, r_qty, w_addr, w_qty, w_bytes = struct.unpack(">HHHHB", data[:9])
                    payload["read_starting_address"] = r_addr
                    payload["read_quantity"] = r_qty
                    payload["write_starting_address"] = w_addr
                    payload["write_quantity"] = w_qty
                    payload["write_byte_count"] = w_bytes

            case 0x2B:
                # Encapsulated Interface Transport (MEI)
                if len(data) >= 1:
                    mei_type = data[0]
                    payload["mei_type"] = mei_type
                    if mei_type == 0x0E and len(data) >= 3:
                        # Read Device Identification
                        payload["read_device_id_code"] = data[1]
                        payload["object_id"] = data[2]

            case 0x08:
                # Diagnostics
                if len(data) >= 4:
                    sub_function, diag_data = struct.unpack(">HH", data[:4])
                    payload["sub_function"] = sub_function
                    payload["diagnostic_data"] = diag_data
