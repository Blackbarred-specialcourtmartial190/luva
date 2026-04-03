"""BACnet/IP (ASHRAE 135) — BVLC + NPDU/APDU subset for passive visibility."""

from __future__ import annotations

import logging
import struct
from typing import Optional

from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.base import BaseParser, ProtocolFrame

logger = logging.getLogger(__name__)

# BVLC function codes (BACnet/IP Annex J)
BVLC_FUNCTIONS: dict[int, str] = {
    0x00: "BVLC-Result",
    0x01: "Write-Broadcast-Distribution-Table",
    0x02: "Read-Broadcast-Distribution-Table",
    0x03: "Read-Broadcast-Distribution-Table-Ack",
    0x04: "Forwarded-NPDU",
    0x05: "Register-Foreign-Device",
    0x06: "Read-Foreign-Device-Table",
    0x07: "Delete-Foreign-Device-Table-Entry",
    0x08: "Distribute-Broadcast-To-Network",
    0x09: "Original-Unicast-NSDU",
    0x0A: "Original-Unicast-NPDU",
    0x0B: "Original-Broadcast-NPDU",
    0x0C: "Forwarded-NSDU",
}

# Confirmed and unconfirmed service choices (subset — OT-relevant)
BACNET_SERVICES: dict[int, str] = {
    0x00: "AcknowledgeAlarm",
    0x01: "COVNotification",
    0x02: "EventNotification",
    0x03: "GetAlarmSummary",
    0x04: "GetEnrollmentSummary",
    0x05: "SubscribeCOV",
    0x06: "AtomicReadFile",
    0x07: "AtomicWriteFile",
    0x08: "AddListElement",
    0x09: "RemoveListElement",
    0x0A: "CreateObject",
    0x0B: "DeleteObject",
    0x0C: "ReadProperty",
    0x0D: "ReadPropertyConditional",
    0x0E: "ReadPropertyMultiple",
    0x0F: "WriteProperty",
    0x10: "WritePropertyMultiple",
    0x11: "DeviceCommunicationControl",
    0x12: "ConfirmedPrivateTransfer",
    0x13: "ConfirmedTextMessage",
    0x14: "ReinitializeDevice",
    0x15: "VTOpen",
    0x16: "VTClose",
    0x17: "VTData",
    0x18: "Authenticate",
    0x19: "RequestKey",
    0x1A: "ReadRange",
    0x1B: "LifeSafetyOperation",
    0x1C: "SubscribeCOVProperty",
    0x1D: "GetEventInformation",
    0x1E: "WriteGroup",
    0x1F: "SubscribeCOVPropertyMultiple",
    0x20: "ConfirmedCOVNotificationMultiple",
    0x21: "ConfirmedAuditNotification",
    0x22: "AuditLogQuery",
}

UNCONFIRMED_SERVICES: dict[int, str] = {
    0x00: "I-Am",
    0x01: "I-Have",
    0x02: "UnconfirmedCOVNotification",
    0x03: "UnconfirmedEventNotification",
    0x04: "UnconfirmedPrivateTransfer",
    0x05: "UnconfirmedTextMessage",
    0x06: "TimeSynchronization",
    0x07: "Who-Has",
    0x08: "Who-Is",
    0x09: "UTC-TimeSynchronization",
    0x0A: "WriteGroup",
    0x0B: "UnconfirmedCOVNotificationMultiple",
    0x0C: "UnconfirmedAuditNotification",
    0x0D: "Who-Am-I",
    0x0E: "You-Are",
}


class BACnetParser(BaseParser):
    """BACnet/IPv4: BVLC header and best-effort APDU service extraction."""

    PROTOCOL_NAME = "BACnet"
    PROTOCOL_SLUG = "bacnet"
    DEFAULT_PORTS = [47808]
    PAYLOAD_HEURISTIC = True

    FUNCTION_CODES = BACNET_SERVICES

    WRITE_FUNCTION_CODES = {
        0x07,  # AtomicWriteFile
        0x08,  # AddListElement
        0x09,  # RemoveListElement
        0x0A,  # CreateObject
        0x0B,  # DeleteObject
        0x0F,  # WriteProperty
        0x10,  # WritePropertyMultiple
        0x11,  # DeviceCommunicationControl
        0x14,  # ReinitializeDevice
        0x1B,  # LifeSafetyOperation
        0x1E,  # WriteGroup
    }
    DIAGNOSTIC_FUNCTION_CODES = {0x03, 0x04, 0x12, 0x18, 0x19, 0x1A, 0x22}
    CONTROL_FUNCTION_CODES = {0x11, 0x14, 0x1B}  # DCC, reinit, life safety

    def can_parse(self, packet: PacketMetadata) -> bool:
        if packet.transport not in ("UDP", "TCP"):
            return False
        if packet.src_port in self.DEFAULT_PORTS or packet.dst_port in self.DEFAULT_PORTS:
            return True
        if packet.payload and len(packet.payload) >= 4 and packet.payload[0] == 0x81:
            return True
        return False

    def parse(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        if not packet.payload or len(packet.payload) < 4:
            return None
        try:
            return self._parse_bvlc(packet)
        except Exception as e:
            logger.debug("BACnet parse error (packet #%s): %s", packet.packet_number, e)
            return None

    def _skip_npdu(self, data: bytes, start: int) -> int:
        """Advance index past NPDU control and optional DNET/SNET routing."""
        if start >= len(data):
            return start
        ctrl = data[start]
        start += 1
        if ctrl & 0x80:
            return len(data)
        if ctrl & 0x20:
            if start + 4 > len(data):
                return start
            dlen = data[start + 3]
            start += 4 + dlen
        if ctrl & 0x10:
            if start + 4 > len(data):
                return start
            slen = data[start + 3]
            start += 4 + slen
        if (ctrl & 0x20) or (ctrl & 0x10):
            if start < len(data):
                start += 1
        return start

    def _parse_apdu(self, apdu: bytes) -> tuple[Optional[int], Optional[str], str]:
        if len(apdu) < 1:
            return None, None, "unknown"
        pdu_type = (apdu[0] >> 4) & 0x0F
        if pdu_type == 0 and len(apdu) >= 5:
            service = apdu[4]
            name = BACNET_SERVICES.get(service, f"ConfirmedService(0x{service:02X})")
            return service, name, "confirmed-request"
        if pdu_type == 1 and len(apdu) >= 2:
            service = apdu[1]
            name = UNCONFIRMED_SERVICES.get(service, f"UnconfirmedService(0x{service:02X})")
            return service, name, "unconfirmed-request"
        if pdu_type == 2:
            return None, "SimpleACK", "simple-ack"
        if pdu_type == 3 and len(apdu) >= 4:
            service = apdu[3]
            name = BACNET_SERVICES.get(service, f"ComplexACK(0x{service:02X})")
            return service, name, "complex-ack"
        if pdu_type == 5 and len(apdu) >= 4:
            service = apdu[3]
            return service, f"Error({service})", "error"
        return None, f"APDU-type-{pdu_type}", "other"

    def _parse_bvlc(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        data = packet.payload
        if data[0] != 0x81:
            return None
        func = data[1]
        msg_len = struct.unpack("!H", data[2:4])[0]
        func_name = BVLC_FUNCTIONS.get(func, f"BVLC-0x{func:02X}")
        payload: dict = {
            "bvlc_function": func,
            "bvlc_function_name": func_name,
            "bvlc_length": msg_len,
        }
        service_code: Optional[int] = None
        service_name: Optional[str] = None
        message_type = func_name

        if func in (0x0A, 0x0B, 0x04) and len(data) > 4:
            apdu_start = self._skip_npdu(data, 4)
            if apdu_start < len(data):
                apdu = data[apdu_start:]
                sc, sn, apdu_kind = self._parse_apdu(apdu)
                service_code = sc
                service_name = sn
                payload["apdu_kind"] = apdu_kind
                if sc is not None:
                    payload["service_choice"] = sc
                message_type = sn or func_name

        apdu_kind = payload.get("apdu_kind", "")
        # Avoid conflating confirmed vs unconfirmed service numbers (same byte, different meaning).
        frame = self._build_frame(
            packet,
            function_code=None,
            payload=payload,
            is_request=func in (0x0A, 0x0B),
            message_type=message_type,
        )
        if service_name:
            frame.function_name = service_name
        if service_code is not None:
            frame.function_code = service_code

        if apdu_kind == "confirmed-request" and service_code is not None:
            if service_code in self.WRITE_FUNCTION_CODES:
                frame.is_write_operation = True
                frame.risk_note = "Write operation — data modification risk"
            if service_code in self.DIAGNOSTIC_FUNCTION_CODES:
                frame.is_diagnostic = True
            if service_code in self.CONTROL_FUNCTION_CODES:
                frame.is_control_command = True
                frame.risk_note = "Control command — operational impact risk"
        elif apdu_kind == "unconfirmed-request" and service_code is not None:
            if service_code in {0x00, 0x01, 0x07, 0x08, 0x0D, 0x0E}:
                frame.is_diagnostic = True
                frame.risk_note = "Diagnostic/discovery — information disclosure risk"
            if service_code == 0x0A:
                frame.is_write_operation = True
                frame.risk_note = "Write operation — data modification risk"
        elif apdu_kind == "error":
            frame.is_exception = True
        return frame
