"""EtherNet/IP + CIP parser."""

from __future__ import annotations

import struct
import logging
from typing import Optional

from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.base import BaseParser, ProtocolFrame

logger = logging.getLogger(__name__)


class ENIPParser(BaseParser):
    """EtherNet/IP encapsulation + CIP (subset)."""

    PROTOCOL_NAME = "EtherNet/IP"
    PROTOCOL_SLUG = "enip"
    DEFAULT_PORTS = [44818, 2222]
    PAYLOAD_HEURISTIC = True

    # EtherNet/IP Commands
    ENIP_COMMANDS = {
        0x0001: "ListServices",
        0x0004: "ListInterfaces",
        0x0063: "ListIdentity",
        0x0064: "ListInterfaces",
        0x0065: "RegisterSession",
        0x0066: "UnregisterSession",
        0x006F: "SendRRData",
        0x0070: "SendUnitData",
        0x0072: "IndicateStatus",
        0x0073: "Cancel",
    }

    # CIP Service Codes
    CIP_SERVICES = {
        0x01: "Get Attributes All",
        0x02: "Set Attributes All",
        0x03: "Get Attribute List",
        0x04: "Set Attribute List",
        0x05: "Reset",
        0x06: "Start",
        0x07: "Stop",
        0x08: "Create",
        0x09: "Delete",
        0x0A: "Multiple Service Packet",
        0x0D: "Apply Attributes",
        0x0E: "Get Attribute Single",
        0x10: "Set Attribute Single",
        0x14: "Find Next Object Instance",
        0x16: "Restore",
        0x18: "Save",
        0x19: "No Operation",
        0x1A: "Get Member",
        0x1B: "Set Member",
        0x1C: "Insert Member",
        0x1D: "Remove Member",
        0x4B: "Execute PCCC",
        0x4C: "Read Tag",
        0x4D: "Write Tag",
        0x4E: "Read Tag Fragmented",
        0x4F: "Write Tag Fragmented",
        0x52: "Read Modify Write Tag",
        0x53: "Read Tag",
        0x54: "Get Instance Attribute List",
        0x55: "Get Member Attribute List",
    }

    FUNCTION_CODES = CIP_SERVICES

    WRITE_FUNCTION_CODES = {0x02, 0x04, 0x10, 0x1B, 0x1C, 0x4D, 0x4F, 0x52}
    DIAGNOSTIC_FUNCTION_CODES = {0x01, 0x03, 0x0E, 0x14, 0x1A, 0x4C, 0x4E}
    CONTROL_FUNCTION_CODES = {0x05, 0x06, 0x07, 0x08, 0x09}  # Reset, Start, Stop, Create, Delete

    # CIP Status Codes
    CIP_STATUS = {
        0x00: "Success",
        0x01: "Connection failure",
        0x02: "Resource unavailable",
        0x03: "Invalid parameter value",
        0x04: "Path segment error",
        0x05: "Path destination unknown",
        0x06: "Partial transfer",
        0x08: "Service not supported",
        0x09: "Invalid attribute value",
        0x0A: "Attribute list error",
        0x0B: "Already in requested mode/state",
        0x0C: "Object state conflict",
        0x0D: "Object already exists",
        0x0E: "Attribute not settable",
        0x0F: "Privilege violation",
        0x10: "Device state conflict",
        0x11: "Reply data too large",
        0x14: "Not enough data",
        0x15: "Attribute not supported",
        0x16: "Too much data",
        0x1C: "Key failure in path",
        0xFF: "Vendor specific error",
    }

    def can_parse(self, packet: PacketMetadata) -> bool:
        """Port/payload heuristic for ENIP."""
        if packet.src_port in self.DEFAULT_PORTS or packet.dst_port in self.DEFAULT_PORTS:
            return True

        if packet.payload and len(packet.payload) >= 24:
            try:
                command = struct.unpack("<H", packet.payload[:2])[0]
                if command in self.ENIP_COMMANDS:
                    return True
            except struct.error:
                pass

        return False

    def parse(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        """Parse ENIP encapsulation into ProtocolFrame."""
        if not packet.payload or len(packet.payload) < 24:
            return None

        try:
            return self._parse_enip(packet)
        except Exception as e:
            logger.debug("EtherNet/IP parse error (packet #%s): %s", packet.packet_number, e)
            return None

    def _parse_enip(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        """Parse encapsulation header."""
        data = packet.payload

        # Encapsulation Header (24 bytes)
        command = struct.unpack("<H", data[0:2])[0]
        length = struct.unpack("<H", data[2:4])[0]
        session_handle = struct.unpack("<I", data[4:8])[0]
        status = struct.unpack("<I", data[8:12])[0]
        options = struct.unpack("<I", data[20:24])[0]

        command_name = self.ENIP_COMMANDS.get(command, f"Unknown (0x{command:04X})")

        payload_dict = {
            "enip_command": command,
            "enip_command_name": command_name,
            "enip_length": length,
            "session_handle": session_handle,
            "status": status,
            "options": options,
        }

        is_request = packet.dst_port in self.DEFAULT_PORTS
        cip_service = None

        # CIP inside SendRRData / SendUnitData
        if command in (0x006F, 0x0070) and len(data) > 24:
            cip_service = self._parse_cip(data[24:], payload_dict, command)

        return self._build_frame(
            packet=packet,
            function_code=cip_service,
            payload=payload_dict,
            is_request=is_request,
            is_exception=(status != 0),
            message_type=command_name,
        )

    def _parse_cip(self, data: bytes, payload: dict, enip_command: int) -> Optional[int]:
        """Parse CIP service (simplified)."""
        if len(data) < 6:
            return None

        # Interface Handle + Timeout (SendRRData)
        if enip_command == 0x006F:
            interface_handle = struct.unpack("<I", data[0:4])[0]
            timeout = struct.unpack("<H", data[4:6])[0]
            payload["cip_interface_handle"] = interface_handle
            payload["cip_timeout"] = timeout

            # Common Packet Format
            if len(data) > 6:
                return self._parse_cpf(data[6:], payload)

        # SendUnitData
        elif enip_command == 0x0070:
            interface_handle = struct.unpack("<I", data[0:4])[0]
            timeout = struct.unpack("<H", data[4:6])[0]
            payload["cip_interface_handle"] = interface_handle
            payload["cip_timeout"] = timeout

            if len(data) > 6:
                return self._parse_cpf(data[6:], payload)

        return None

    def _parse_cpf(self, data: bytes, payload: dict) -> Optional[int]:
        """Common Packet Format (simplified)."""
        if len(data) < 2:
            return None

        item_count = struct.unpack("<H", data[0:2])[0]
        payload["cpf_item_count"] = item_count

        offset = 2
        cip_service = None

        for i in range(min(item_count, 4)):
            if offset + 4 > len(data):
                break

            type_id = struct.unpack("<H", data[offset:offset + 2])[0]
            item_length = struct.unpack("<H", data[offset + 2:offset + 4])[0]
            offset += 4

            # Connected/Unconnected Data Item (0x00B2 veya 0x00B1)
            if type_id in (0x00B1, 0x00B2) and item_length > 0 and offset + item_length <= len(data):
                item_data = data[offset:offset + item_length]

                # CIP Service byte
                svc_offset = 2 if type_id == 0x00B1 else 0  # Connected data has 2-byte sequence
                if svc_offset < len(item_data):
                    service_byte = item_data[svc_offset]
                    is_response = bool(service_byte & 0x80)
                    actual_service = service_byte & 0x7F

                    cip_service = actual_service
                    payload["cip_service"] = actual_service
                    payload["cip_service_name"] = self.CIP_SERVICES.get(
                        actual_service, f"Unknown (0x{actual_service:02X})"
                    )
                    payload["cip_is_response"] = is_response

                    if is_response and svc_offset + 3 < len(item_data):
                        cip_status = item_data[svc_offset + 2]
                        payload["cip_status"] = cip_status
                        payload["cip_status_name"] = self.CIP_STATUS.get(
                            cip_status, f"Unknown (0x{cip_status:02X})"
                        )

            offset += item_length

        return cip_service
