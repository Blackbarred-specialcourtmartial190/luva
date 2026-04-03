"""SNMP (v1/v2c) — BER envelope and PDU type for passive monitoring visibility."""

from __future__ import annotations

import logging
from typing import Optional

from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.base import BaseParser, ProtocolFrame

logger = logging.getLogger(__name__)

PDU_TYPES: dict[int, str] = {
    0: "GetRequest",
    1: "GetNextRequest",
    2: "Response",
    3: "SetRequest",
    4: "Trap",
    5: "GetBulkRequest",
    6: "InformRequest",
    7: "SNMPv2-Trap",
    8: "Report",
}


def _ber_read_length(data: bytes, i: int) -> tuple[int, int]:
    """Return (length, new_index) for BER length octets."""
    if i >= len(data):
        return 0, i
    b = data[i]
    i += 1
    if b & 0x80:
        n = b & 0x7F
        if n == 0 or n > 4 or i + n > len(data):
            return 0, i
        ln = int.from_bytes(data[i : i + n], "big")
        return ln, i + n
    return b, i


def _parse_snmp_v1v2c_pdu_type(data: bytes) -> tuple[Optional[int], Optional[str], dict]:
    """Best-effort: SEQUENCE { version, community, pdu }."""
    meta: dict = {}
    if len(data) < 8 or data[0] != 0x30:
        return None, None, meta
    i = 1
    seq_len, i = _ber_read_length(data, i)
    end = min(len(data), i + seq_len)

    if i >= end or data[i] != 0x02:
        return None, None, meta
    i += 1
    vlen, i = _ber_read_length(data, i)
    if i + vlen > end:
        return None, None, meta
    version = int.from_bytes(data[i : i + vlen], "big")
    meta["snmp_version"] = version
    i += vlen

    if version == 3:
        return None, "SNMPv3", meta

    if i >= end or data[i] != 0x04:
        return None, None, meta
    i += 1
    clen, i = _ber_read_length(data, i)
    if i + clen > end:
        return None, None, meta
    meta["community_present"] = True
    meta["community_len"] = clen
    i += clen

    if i >= end:
        return None, None, meta
    pdu_tag = data[i]
    meta["pdu_tag"] = pdu_tag
    pdu_type = pdu_tag - 0xA0 if 0xA0 <= pdu_tag <= 0xA8 else None
    if pdu_type is not None and pdu_type in PDU_TYPES:
        return pdu_type, PDU_TYPES[pdu_type], meta
    if pdu_tag == 0xA4:
        return 4, "Trap", meta
    return pdu_type, None, meta


class SNMPParser(BaseParser):
    """SNMP over UDP: classify Get/Set/Trap-style PDUs (no OID walk)."""

    PROTOCOL_NAME = "SNMP"
    PROTOCOL_SLUG = "snmp"
    DEFAULT_PORTS = [161, 162]

    FUNCTION_CODES = PDU_TYPES

    WRITE_FUNCTION_CODES = {3}  # SetRequest
    DIAGNOSTIC_FUNCTION_CODES = {4, 6, 7, 8}  # Trap, Inform, SNMPv2-Trap, Report
    CONTROL_FUNCTION_CODES = set()

    def can_parse(self, packet: PacketMetadata) -> bool:
        if packet.transport != "UDP":
            return False
        if packet.src_port in self.DEFAULT_PORTS or packet.dst_port in self.DEFAULT_PORTS:
            return True
        return False

    def parse(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        if not packet.payload or len(packet.payload) < 8:
            return None
        try:
            return self._parse_snmp(packet)
        except Exception as e:
            logger.debug("SNMP parse error (packet #%s): %s", packet.packet_number, e)
            return None

    def _parse_snmp(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        pdu_type, pdu_name, meta = _parse_snmp_v1v2c_pdu_type(packet.payload)
        if meta.get("snmp_version") is None:
            return None

        payload = dict(meta)
        if pdu_name == "SNMPv3":
            frame = self._build_frame(
                packet,
                function_code=None,
                payload=payload,
                is_request=True,
                message_type="SNMPv3",
            )
            frame.function_name = "SNMPv3"
            frame.is_diagnostic = True
            frame.risk_note = "SNMPv3 — verify auth/priv in scope"
            return frame

        if pdu_name:
            payload["pdu_type_name"] = pdu_name
        if pdu_type is not None:
            display = pdu_name or PDU_TYPES.get(pdu_type, f"PDU-{pdu_type}")
        else:
            display = pdu_name or f"SNMP(tag=0x{meta.get('pdu_tag', 0):02X})"

        frame = self._build_frame(
            packet,
            function_code=pdu_type,
            payload=payload,
            is_request=pdu_type in {0, 1, 3, 5, 6} if pdu_type is not None else True,
            message_type=display,
        )
        frame.function_name = display
        return frame
