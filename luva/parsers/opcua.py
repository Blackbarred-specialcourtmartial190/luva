"""OPC UA Binary parser (subset)."""

from __future__ import annotations

import struct
import logging
from typing import Optional

from luva.engine.pcap_reader import PacketMetadata
from luva.parsers.base import BaseParser, ProtocolFrame

logger = logging.getLogger(__name__)


class OPCUAParser(BaseParser):
    """OPC UA binary: message chunk + service id (heuristic)."""

    PROTOCOL_NAME = "OPC UA"
    PROTOCOL_SLUG = "opcua"
    DEFAULT_PORTS = [4840]
    PAYLOAD_HEURISTIC = True

    # OPC UA Message Types
    MESSAGE_TYPES = {
        "HEL": "Hello",
        "ACK": "Acknowledge",
        "OPN": "Open Secure Channel",
        "MSG": "Message",
        "CLO": "Close Secure Channel",
        "ERR": "Error",
    }

    # OPC UA Service IDs (partial list)
    SERVICE_IDS = {
        # Discovery
        422: "FindServersRequest",
        425: "FindServersResponse",
        428: "GetEndpointsRequest",
        431: "GetEndpointsResponse",
        # Session
        461: "CreateSessionRequest",
        464: "CreateSessionResponse",
        467: "ActivateSessionRequest",
        470: "ActivateSessionResponse",
        473: "CloseSessionRequest",
        476: "CloseSessionResponse",
        # Node Management
        488: "AddNodesRequest",
        491: "AddNodesResponse",
        494: "AddReferencesRequest",
        497: "AddReferencesResponse",
        500: "DeleteNodesRequest",
        503: "DeleteNodesResponse",
        # View
        527: "BrowseRequest",
        530: "BrowseResponse",
        533: "BrowseNextRequest",
        536: "BrowseNextResponse",
        # Read/Write
        631: "ReadRequest",
        634: "ReadResponse",
        673: "WriteRequest",
        676: "WriteResponse",
        # History (common on historians / SCADA back-end)
        660: "HistoryReadRequest",
        663: "HistoryReadResponse",
        666: "HistoryUpdateRequest",
        669: "HistoryUpdateResponse",
        # Subscription
        787: "CreateSubscriptionRequest",
        790: "CreateSubscriptionResponse",
        826: "DeleteSubscriptionsRequest",
        829: "DeleteSubscriptionsResponse",
        # MonitoredItems
        751: "CreateMonitoredItemsRequest",
        754: "CreateMonitoredItemsResponse",
        781: "DeleteMonitoredItemsRequest",
        784: "DeleteMonitoredItemsResponse",
        # Method
        712: "CallRequest",
        715: "CallResponse",
    }

    FUNCTION_CODES = {k: v for k, v in SERVICE_IDS.items()}

    WRITE_FUNCTION_CODES = {673, 488, 494, 500, 666, 669}  # Write, node mgmt, history update
    DIAGNOSTIC_FUNCTION_CODES = {422, 428, 527, 631, 660, 663}  # Discovery, browse, read, history read
    CONTROL_FUNCTION_CODES = {712}  # Call (method invocation)

    def can_parse(self, packet: PacketMetadata) -> bool:
        """Port + OPC UA message type prefix."""
        if packet.src_port in self.DEFAULT_PORTS or packet.dst_port in self.DEFAULT_PORTS:
            return True

        if packet.payload and len(packet.payload) >= 8:
            try:
                msg_type = packet.payload[:3].decode("ascii")
                if msg_type in self.MESSAGE_TYPES:
                    return True
            except (UnicodeDecodeError, ValueError):
                pass

        return False

    def parse(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        """Parse OPC UA chunk."""
        if not packet.payload or len(packet.payload) < 8:
            return None

        try:
            return self._parse_opcua(packet)
        except Exception as e:
            logger.debug("OPC UA parse error (packet #%s): %s", packet.packet_number, e)
            return None

    def _parse_opcua(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        """Parse message header and body."""
        data = packet.payload

        # Message Header
        try:
            msg_type = data[:3].decode("ascii")
        except (UnicodeDecodeError, ValueError):
            return None

        if msg_type not in self.MESSAGE_TYPES:
            return None

        chunk_type = chr(data[3]) if len(data) > 3 else "?"
        msg_size = struct.unpack("<I", data[4:8])[0] if len(data) >= 8 else 0

        payload_dict = {
            "message_type": msg_type,
            "message_type_name": self.MESSAGE_TYPES.get(msg_type, "Unknown"),
            "chunk_type": chunk_type,
            "message_size": msg_size,
        }

        is_request = packet.dst_port in self.DEFAULT_PORTS
        service_id = None

        match msg_type:
            case "HEL":
                self._parse_hello(data[8:], payload_dict)
            case "ACK":
                self._parse_ack(data[8:], payload_dict)
            case "ERR":
                self._parse_error(data[8:], payload_dict)
            case "OPN":
                self._parse_open_secure_channel(data[8:], payload_dict)
            case "MSG":
                service_id = self._parse_message(data[8:], payload_dict)
            case "CLO":
                payload_dict["action"] = "Close Secure Channel"

        return self._build_frame(
            packet=packet,
            function_code=service_id,
            payload=payload_dict,
            is_request=is_request,
            is_exception=(msg_type == "ERR"),
            message_type=msg_type,
        )

    def _parse_hello(self, data: bytes, payload: dict) -> None:
        """HEL chunk."""
        if len(data) >= 20:
            protocol_version, recv_buf, send_buf, max_msg, max_chunk = struct.unpack("<IIIII", data[:20])
            payload["protocol_version"] = protocol_version
            payload["receive_buffer_size"] = recv_buf
            payload["send_buffer_size"] = send_buf
            payload["max_message_size"] = max_msg
            payload["max_chunk_count"] = max_chunk

            # Endpoint URL
            if len(data) > 24:
                url_length = struct.unpack("<I", data[20:24])[0]
                if url_length > 0 and len(data) >= 24 + url_length:
                    try:
                        payload["endpoint_url"] = data[24:24 + url_length].decode("utf-8")
                    except UnicodeDecodeError:
                        pass

    def _parse_ack(self, data: bytes, payload: dict) -> None:
        """ACK chunk."""
        if len(data) >= 20:
            protocol_version, recv_buf, send_buf, max_msg, max_chunk = struct.unpack("<IIIII", data[:20])
            payload["protocol_version"] = protocol_version
            payload["receive_buffer_size"] = recv_buf
            payload["send_buffer_size"] = send_buf
            payload["max_message_size"] = max_msg
            payload["max_chunk_count"] = max_chunk

    def _parse_error(self, data: bytes, payload: dict) -> None:
        """ERR chunk."""
        if len(data) >= 4:
            error_code = struct.unpack("<I", data[:4])[0]
            payload["error_code"] = error_code

            if len(data) >= 8:
                reason_len = struct.unpack("<I", data[4:8])[0]
                if reason_len > 0 and len(data) >= 8 + reason_len:
                    try:
                        payload["error_reason"] = data[8:8 + reason_len].decode("utf-8")
                    except UnicodeDecodeError:
                        pass

    def _parse_open_secure_channel(self, data: bytes, payload: dict) -> None:
        """OPN chunk."""
        if len(data) >= 8:
            secure_channel_id = struct.unpack("<I", data[:4])[0]
            payload["secure_channel_id"] = secure_channel_id

    def _parse_message(self, data: bytes, payload: dict) -> Optional[int]:
        """Best-effort service id from MSG body."""
        if len(data) < 16:
            return None

        # Secure Channel ID + Security Token ID
        secure_ch_id = struct.unpack("<I", data[:4])[0]
        payload["secure_channel_id"] = secure_ch_id

        # Heuristic: scan for known service id values in encoded body
        for offset in range(8, min(len(data) - 4, 100), 2):
            try:
                candidate = struct.unpack("<H", data[offset:offset + 2])[0]
                if candidate in self.SERVICE_IDS:
                    service_name = self.SERVICE_IDS[candidate]
                    sid = int(candidate)
                    payload["service_id"] = sid
                    payload["service_name"] = service_name
                    payload["service_is_request"] = service_name.endswith("Request")
                    return sid
            except struct.error:
                break

        return None
