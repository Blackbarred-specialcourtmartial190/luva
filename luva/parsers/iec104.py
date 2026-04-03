"""IEC 60870-5-104 parser (APCI + ASDU subset)."""

from __future__ import annotations

import struct
import logging
from typing import Any, Optional

from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.base import BaseParser, ProtocolFrame

logger = logging.getLogger(__name__)


class IEC104Parser(BaseParser):
    """IEC 104: APCI + ASDU (subset)."""

    PROTOCOL_NAME = "IEC 104"
    PROTOCOL_SLUG = "iec104"
    DEFAULT_PORTS = [2404]
    PAYLOAD_HEURISTIC = True

    # APCI Start Byte
    START_BYTE = 0x68

    # ASDU Type IDs (Monitoring direction — process telecontrol)
    ASDU_TYPES = {
        # Monitoring (station → control center)
        1: "M_SP_NA_1 (Single-point information)",
        2: "M_SP_TA_1 (Single-point with time tag)",
        3: "M_DP_NA_1 (Double-point information)",
        4: "M_DP_TA_1 (Double-point with time tag)",
        5: "M_ST_NA_1 (Step position)",
        7: "M_BO_NA_1 (Bitstring 32 bit)",
        9: "M_ME_NA_1 (Measured normalized)",
        11: "M_ME_NB_1 (Measured scaled)",
        13: "M_ME_NC_1 (Measured short floating)",
        15: "M_IT_NA_1 (Integrated totals)",
        20: "M_PS_NA_1 (Packed single-point)",
        21: "M_ME_ND_1 (Measured normalized without quality)",
        30: "M_SP_TB_1 (Single-point with CP56Time2a)",
        31: "M_DP_TB_1 (Double-point with CP56Time2a)",
        32: "M_ST_TB_1 (Step position with CP56Time2a)",
        34: "M_ME_TD_1 (Measured normalized with CP56Time2a)",
        35: "M_ME_TE_1 (Measured scaled with CP56Time2a)",
        36: "M_ME_TF_1 (Measured short floating with CP56Time2a)",

        # Control (control center → station)
        45: "C_SC_NA_1 (Single command)",
        46: "C_DC_NA_1 (Double command)",
        47: "C_RC_NA_1 (Regulating step command)",
        48: "C_SE_NA_1 (Set-point normalized)",
        49: "C_SE_NB_1 (Set-point scaled)",
        50: "C_SE_NC_1 (Set-point short floating)",
        51: "C_BO_NA_1 (Bitstring 32 bit command)",
        58: "C_SC_TA_1 (Single command with CP56Time2a)",
        59: "C_DC_TA_1 (Double command with CP56Time2a)",
        60: "C_RC_TA_1 (Regulating step with CP56Time2a)",

        # System commands
        100: "C_IC_NA_1 (Interrogation command)",
        101: "C_CI_NA_1 (Counter interrogation command)",
        102: "C_RD_NA_1 (Read command)",
        103: "C_CS_NA_1 (Clock synchronization)",
        104: "C_TS_NA_1 (Test command)",
        105: "C_RP_NA_1 (Reset process command)",
        106: "C_CD_NA_1 (Delay acquisition command)",
        107: "C_TS_TA_1 (Test command with CP56Time2a)",

        # Parameter commands
        110: "P_ME_NA_1 (Parameter of normalized value)",
        111: "P_ME_NB_1 (Parameter of scaled value)",
        112: "P_ME_NC_1 (Parameter of short floating)",
        113: "P_AC_NA_1 (Parameter activation)",

        # File transfer
        120: "F_FR_NA_1 (File ready)",
        121: "F_SR_NA_1 (Section ready)",
        122: "F_SC_NA_1 (Call directory/file/section)",
        123: "F_LS_NA_1 (Last section/segment)",
        124: "F_AF_NA_1 (ACK file/section)",
        125: "F_SG_NA_1 (Segment)",
        126: "F_DR_TA_1 (Directory)",
    }

    # Cause of Transmission (COT)
    COT_VALUES = {
        1: "Periodic/Cyclic",
        2: "Background scan",
        3: "Spontaneous",
        4: "Initialized",
        5: "Request/Requested",
        6: "Activation",
        7: "Activation confirmation",
        8: "Deactivation",
        9: "Deactivation confirmation",
        10: "Activation termination",
        13: "File transfer",
        20: "Interrogated by station",
        37: "Interrogated by counter",
        44: "Unknown type",
        45: "Unknown cause",
        46: "Unknown ASDU address",
        47: "Unknown IOA",
    }

    FUNCTION_CODES = ASDU_TYPES

    # Control-type ASDU types (writes/commands)
    WRITE_FUNCTION_CODES = {45, 46, 47, 48, 49, 50, 51, 58, 59, 60}
    DIAGNOSTIC_FUNCTION_CODES = {100, 101, 102, 104, 107}
    CONTROL_FUNCTION_CODES = {103, 105, 106}  # Clock sync, reset process, delay acq

    # APCI Frame Types
    FRAME_I = "I-frame"   # Information transfer
    FRAME_S = "S-frame"   # Supervisory
    FRAME_U = "U-frame"   # Unnumbered

    def can_parse(self, packet: PacketMetadata) -> bool:
        """Port 2404 + 0x68 APCI start."""
        if packet.src_port in self.DEFAULT_PORTS or packet.dst_port in self.DEFAULT_PORTS:
            return True

        if packet.payload and len(packet.payload) >= 2:
            return packet.payload[0] == self.START_BYTE

        return False

    def parse(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        """Parse APCI/ASDU."""
        if not packet.payload or len(packet.payload) < 6:
            return None

        try:
            return self._parse_iec104(packet)
        except Exception as e:
            logger.debug("IEC 104 parse error (packet #%s): %s", packet.packet_number, e)
            return None

    def _parse_iec104(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        """APCI + ASDU body."""
        data = packet.payload

        # APCI Header
        start_byte = data[0]
        if start_byte != self.START_BYTE:
            return None

        apdu_length = data[1]
        control_fields = data[2:6]

        payload_dict: dict[str, Any] = {
            "apdu_length": apdu_length,
        }

        # Frame tipi belirleme
        frame_type = self._determine_frame_type(control_fields)
        payload_dict["frame_type"] = frame_type

        is_request = packet.dst_port in self.DEFAULT_PORTS
        asdu_type_id = None

        match frame_type:
            case self.FRAME_I:
                # I-frame carries ASDU
                send_seq = (struct.unpack("<H", control_fields[0:2])[0]) >> 1
                recv_seq = (struct.unpack("<H", control_fields[2:4])[0]) >> 1
                payload_dict["send_sequence"] = send_seq
                payload_dict["recv_sequence"] = recv_seq

                # ASDU
                if len(data) > 6:
                    asdu_type_id = self._parse_asdu(data[6:], payload_dict)

            case self.FRAME_S:
                # S-frame: Supervisory (onay)
                recv_seq = (struct.unpack("<H", control_fields[2:4])[0]) >> 1
                payload_dict["recv_sequence"] = recv_seq

            case self.FRAME_U:
                # U-frame: unnumbered control
                u_type = control_fields[0]
                u_function = self._decode_u_function(u_type)
                payload_dict["u_function"] = u_function

        return self._build_frame(
            packet=packet,
            function_code=asdu_type_id,
            payload=payload_dict,
            is_request=is_request,
            message_type=frame_type,
        )

    def _determine_frame_type(self, control_fields: bytes) -> str:
        """APCI control field'dan frame tipini belirler."""
        first_byte = control_fields[0]

        if not (first_byte & 0x01):
            return self.FRAME_I   # LSB = 0 → I-frame
        elif first_byte & 0x03 == 0x01:
            return self.FRAME_S   # bit0=1, bit1=0 → S-frame
        else:
            return self.FRAME_U   # bit0=1, bit1=1 → U-frame

    def _decode_u_function(self, u_byte: int) -> str:
        """U-frame function label."""
        if u_byte & 0x04:
            return "STARTDT ACT" if u_byte & 0x04 else ""
        if u_byte & 0x08:
            return "STARTDT CON"
        if u_byte & 0x10:
            return "STOPDT ACT"
        if u_byte & 0x20:
            return "STOPDT CON"
        if u_byte & 0x40:
            return "TESTFR ACT"
        if u_byte & 0x80:
            return "TESTFR CON"

        # Bitwise decode
        functions = []
        if u_byte & 0x04:
            functions.append("STARTDT ACT")
        if u_byte & 0x08:
            functions.append("STARTDT CON")
        if u_byte & 0x10:
            functions.append("STOPDT ACT")
        if u_byte & 0x20:
            functions.append("STOPDT CON")
        if u_byte & 0x40:
            functions.append("TESTFR ACT")
        if u_byte & 0x80:
            functions.append("TESTFR CON")

        return ", ".join(functions) if functions else f"Unknown (0x{u_byte:02X})"

    def _parse_asdu(self, data: bytes, payload: dict) -> Optional[int]:
        """ASDU fields (subset)."""
        if len(data) < 6:
            return None

        type_id = data[0]
        variable_struct_qualifier = data[1]
        sq = bool(variable_struct_qualifier & 0x80)  # SQ bit
        num_objects = variable_struct_qualifier & 0x7F

        cot_byte = data[2]
        cause_of_transmission = cot_byte & 0x3F
        pn = bool(cot_byte & 0x40)  # P/N bit (positive/negative)
        test = bool(cot_byte & 0x80)  # Test bit

        originator_address = data[3]
        asdu_address = struct.unpack("<H", data[4:6])[0]

        payload["asdu_type_id"] = type_id
        payload["asdu_type_name"] = self.ASDU_TYPES.get(type_id, f"Unknown ({type_id})")
        payload["sq"] = sq
        payload["num_objects"] = num_objects
        payload["cause_of_transmission"] = cause_of_transmission
        payload["cot_name"] = self.COT_VALUES.get(cause_of_transmission, f"Unknown ({cause_of_transmission})")
        payload["positive_negative"] = "Negative" if pn else "Positive"
        payload["test_mode"] = test
        payload["originator_address"] = originator_address
        payload["asdu_address"] = asdu_address

        # IOA (Information Object Address) — ilk nesneyi oku
        if len(data) > 6:
            # IOA: 3 byte (IEC 104'te)
            if len(data) >= 9:
                ioa = struct.unpack("<I", data[6:9] + b"\x00")[0]
                payload["first_ioa"] = ioa

        return type_id
