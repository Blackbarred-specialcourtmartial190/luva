"""DNP3 parser — data link + application (simplified)."""

from __future__ import annotations

import struct
import logging
from typing import Optional

from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.base import BaseParser, ProtocolFrame

logger = logging.getLogger(__name__)


class DNP3Parser(BaseParser):
    """DNP3: link + transport + application (subset)."""

    PROTOCOL_NAME = "DNP3"
    PROTOCOL_SLUG = "dnp3"
    DEFAULT_PORTS = [20000]
    PAYLOAD_HEURISTIC = True

    # DNP3 Start Bytes
    START_BYTES = bytes([0x05, 0x64])

    # Application Layer Function Codes
    FUNCTION_CODES = {
        0x00: "Confirm",
        0x01: "Read",
        0x02: "Write",
        0x03: "Select",
        0x04: "Operate",
        0x05: "Direct Operate",
        0x06: "Direct Operate No Ack",
        0x07: "Immediate Freeze",
        0x08: "Immediate Freeze No Ack",
        0x09: "Freeze and Clear",
        0x0A: "Freeze and Clear No Ack",
        0x0B: "Freeze at Time",
        0x0C: "Freeze at Time No Ack",
        0x0D: "Cold Restart",
        0x0E: "Warm Restart",
        0x0F: "Initialize Data",
        0x10: "Initialize Application",
        0x11: "Start Application",
        0x12: "Stop Application",
        0x13: "Save Configuration",
        0x14: "Enable Unsolicited",
        0x15: "Disable Unsolicited",
        0x16: "Assign Class",
        0x17: "Delay Measurement",
        0x18: "Record Current Time",
        0x19: "Open File",
        0x1A: "Close File",
        0x1B: "Delete File",
        0x1C: "Get File Info",
        0x1D: "Authenticate File",
        0x1E: "Abort File",
        # Response function codes
        0x81: "Response",
        0x82: "Unsolicited Response",
        0x83: "Authentication Response",
    }

    WRITE_FUNCTION_CODES = {0x02, 0x03, 0x04, 0x05, 0x06}
    DIAGNOSTIC_FUNCTION_CODES = {0x17, 0x18, 0x1C}
    CONTROL_FUNCTION_CODES = {
        0x0D, 0x0E,  # Cold/Warm Restart
        0x0F, 0x10, 0x11, 0x12,  # Init/Start/Stop Application
        0x13,  # Save Configuration
        0x07, 0x08, 0x09, 0x0A,  # Freeze commands
    }

    # DNP3 Internal Indications (IIN)
    IIN_FLAGS = {
        0x0001: "All Stations",
        0x0002: "Class 1 Data Available",
        0x0004: "Class 2 Data Available",
        0x0008: "Class 3 Data Available",
        0x0010: "Time Sync Required",
        0x0020: "Local Control",
        0x0040: "Device Trouble",
        0x0080: "Device Restart",
        0x0100: "No Function Code Support",
        0x0200: "Object Unknown",
        0x0400: "Parameter Error",
        0x0800: "Event Buffer Overflow",
        0x1000: "Already Executing",
        0x2000: "Configuration Corrupt",
        0x8000: "Reserved (15)",
    }

    def can_parse(self, packet: PacketMetadata) -> bool:
        """UDP/TCP port + 0x05 0x64 heuristic."""
        if packet.src_port in self.DEFAULT_PORTS or packet.dst_port in self.DEFAULT_PORTS:
            return True

        if packet.payload and len(packet.payload) >= 3:
            return packet.payload[:2] == self.START_BYTES

        return False

    def parse(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        """Parse DNP3 frame."""
        if not packet.payload or len(packet.payload) < 10:
            return None

        try:
            return self._parse_dnp3(packet)
        except Exception as e:
            logger.debug("DNP3 parse error (packet #%s): %s", packet.packet_number, e)
            return None

    def _parse_dnp3(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        """Data link + application (simplified)."""
        data = packet.payload

        # Data Link Layer Header
        if data[:2] != self.START_BYTES:
            return None

        dl_length = data[2]
        dl_control = data[3]
        dl_destination = struct.unpack("<H", data[4:6])[0]
        dl_source = struct.unpack("<H", data[6:8])[0]

        # Control byte
        dl_direction = bool(dl_control & 0x80)  # DIR bit
        dl_primary = bool(dl_control & 0x40)    # PRM bit
        dl_func_code = dl_control & 0x0F        # Function code

        payload_dict = {
            "dl_length": dl_length,
            "dl_destination": dl_destination,
            "dl_source": dl_source,
            "dl_direction": "Master→Outstation" if dl_direction else "Outstation→Master",
            "dl_primary": dl_primary,
            "dl_function_code": dl_func_code,
        }

        # Skip CRC blocks to reach application layer
        # DNP3 CRC her 16 byte'ta 2 byte CRC ekler
        app_data = self._remove_crc(data[10:], dl_length - 5)

        if not app_data or len(app_data) < 2:
            return self._build_frame(
                packet=packet,
                function_code=None,
                payload=payload_dict,
                is_request=dl_primary,
                message_type="dl_only",
            )

        # Transport Layer
        transport_header = app_data[0]
        transport_fin = bool(transport_header & 0x80)
        transport_fir = bool(transport_header & 0x40)
        transport_seq = transport_header & 0x3F

        payload_dict["transport_fin"] = transport_fin
        payload_dict["transport_fir"] = transport_fir
        payload_dict["transport_seq"] = transport_seq

        # Application Layer
        if len(app_data) < 4:
            return self._build_frame(
                packet=packet,
                function_code=None,
                payload=payload_dict,
                is_request=dl_primary,
                message_type="transport_only",
            )

        app_control = app_data[1]
        app_func_code = app_data[2]

        app_fir = bool(app_control & 0x80)
        app_fin = bool(app_control & 0x40)
        app_con = bool(app_control & 0x20)
        app_uns = bool(app_control & 0x10)
        app_seq = app_control & 0x0F

        payload_dict["app_fir"] = app_fir
        payload_dict["app_fin"] = app_fin
        payload_dict["app_confirm_required"] = app_con
        payload_dict["app_unsolicited"] = app_uns
        payload_dict["app_sequence"] = app_seq

        # Response ise IIN bitlerini oku
        is_response = app_func_code >= 0x80
        if is_response and len(app_data) >= 5:
            iin = struct.unpack("<H", app_data[3:5])[0]
            payload_dict["iin"] = iin
            payload_dict["iin_flags"] = self._decode_iin(iin)

        # Object headers (simplified)
        obj_offset = 5 if is_response else 3
        if len(app_data) > obj_offset:
            objects = self._parse_object_headers(app_data[obj_offset:])
            if objects:
                payload_dict["objects"] = objects

        return self._build_frame(
            packet=packet,
            function_code=app_func_code,
            payload=payload_dict,
            is_request=not is_response,
            is_exception=False,
            message_type="response" if is_response else "request",
        )

    def _remove_crc(self, data: bytes, expected_length: int) -> bytes:
        """Strip 2-byte CRC every 16 bytes (simplified)."""
        result = bytearray()
        offset = 0
        remaining = expected_length

        while offset < len(data) and remaining > 0:
            chunk_size = min(16, remaining)
            if offset + chunk_size > len(data):
                chunk_size = len(data) - offset

            result.extend(data[offset:offset + chunk_size])
            remaining -= chunk_size
            offset += chunk_size + 2  # +2 CRC atlama

        return bytes(result)

    def _decode_iin(self, iin: int) -> list[str]:
        """Decode IIN bits to flag names."""
        flags = []
        for bit_mask, name in self.IIN_FLAGS.items():
            if iin & bit_mask:
                flags.append(name)
        return flags

    def _parse_object_headers(self, data: bytes) -> list[dict]:
        """Parse object headers (simplified)."""
        objects: list[dict] = []
        offset = 0

        while offset + 3 <= len(data) and len(objects) < 10:
            group = data[offset]
            variation = data[offset + 1]
            qualifier = data[offset + 2]
            range_code = qualifier & 0x0F

            obj = {
                "group": group,
                "variation": variation,
                "qualifier": qualifier,
                "group_name": self._get_group_name(group),
            }
            objects.append(obj)

            # Skip range per qualifier (simplified)
            match range_code:
                case 0x00 | 0x01:  # 1-byte start/stop
                    offset += 5
                case 0x02 | 0x03:  # 2-byte start/stop
                    offset += 7
                case 0x04 | 0x05:  # 4-byte start/stop
                    offset += 11
                case 0x06:  # All objects
                    offset += 3
                case 0x07 | 0x08:  # Count
                    offset += 4
                case _:
                    offset += 3
                    break  # Bilinmeyen qualifier, dur

        return objects

    @staticmethod
    def _get_group_name(group: int) -> str:
        """Human name for object group."""
        groups = {
            1: "Binary Input",
            2: "Binary Input Event",
            3: "Double-bit Binary Input",
            10: "Binary Output",
            12: "CROB (Control Relay Output Block)",
            20: "Counter",
            21: "Frozen Counter",
            30: "Analog Input",
            32: "Analog Input Event",
            40: "Analog Output Status",
            41: "Analog Output Block",
            50: "Time and Date",
            60: "Class Data",
            70: "File Control",
            80: "Internal Indications",
            110: "Octet String",
            120: "Authentication",
        }
        return groups.get(group, f"Group {group}")
