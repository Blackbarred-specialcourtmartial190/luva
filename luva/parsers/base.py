"""BaseParser — abstract base class for all protocol parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from luva.engine.pcap_reader import PacketMetadata


@dataclass
class ProtocolFrame:
    """Normalized protocol frame.

    Each parser maps a raw packet into this shape so upper layers stay protocol-agnostic.
    """
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str                          # "Modbus", "S7", "DNP3", etc.
    protocol_slug: str = ""                # lowercase key for CLI/YAML rules, e.g. "modbus"
    function_code: Optional[int] = None
    function_name: Optional[str] = None

    # Structured payload fields
    payload: dict = field(default_factory=dict)

    # Message semantics
    is_request: bool = True                # True=request, False=response
    is_exception: bool = False             # Error/exception response?
    message_type: Optional[str] = None     # Protocol-specific message type

    # Raw bytes
    raw_bytes: bytes = field(default_factory=bytes, repr=False)
    packet_number: Optional[int] = None
    pcap_file: Optional[str] = None

    # Risk classification
    is_write_operation: bool = False        # Write/modify operation?
    is_diagnostic: bool = False             # Diagnostic/discovery?
    is_control_command: bool = False        # Control command? (e.g. PLC start/stop)
    risk_note: Optional[str] = None

    def to_dict(self) -> dict:
        """JSON-serializable dict."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "protocol_slug": self.protocol_slug,
            "function_code": self.function_code,
            "function_name": self.function_name,
            "payload": self.payload,
            "is_request": self.is_request,
            "is_exception": self.is_exception,
            "message_type": self.message_type,
            "is_write_operation": self.is_write_operation,
            "is_diagnostic": self.is_diagnostic,
            "is_control_command": self.is_control_command,
            "risk_note": self.risk_note,
            "packet_number": self.packet_number,
            "pcap_file": self.pcap_file,
        }


class BaseParser(ABC):
    """Abstract base for ICS protocol parsers.

    New protocol support should subclass this. Parsers can be selected at runtime by slug.
    """

    PROTOCOL_NAME: str = ""
    PROTOCOL_SLUG: str = ""  # CLI -p and YAML rule protocol: must match this slug
    DEFAULT_PORTS: list[int] = []
    #: If True, ``can_parse`` may match via payload when no well-known port matches (non-standard ports).
    PAYLOAD_HEURISTIC: bool = False
    FUNCTION_CODES: dict[int, str] = {}

    # Function codes that imply writes
    WRITE_FUNCTION_CODES: set[int] = set()

    # Diagnostic/discovery codes
    DIAGNOSTIC_FUNCTION_CODES: set[int] = set()

    # Control codes (e.g. PLC start/stop)
    CONTROL_FUNCTION_CODES: set[int] = set()

    @abstractmethod
    def can_parse(self, packet: PacketMetadata) -> bool:
        """Return True if this parser should handle the packet (ports + payload heuristics)."""
        ...

    @abstractmethod
    def parse(self, packet: PacketMetadata) -> Optional[ProtocolFrame]:
        """Parse packet into a ProtocolFrame, or None if parsing fails."""
        ...

    def get_function_description(self, function_code: int) -> str:
        """Map function code to a human-readable name."""
        return self.FUNCTION_CODES.get(function_code, f"Unknown (0x{function_code:02X})")

    def is_write_function(self, function_code: int) -> bool:
        """True if the function code indicates a write operation."""
        return function_code in self.WRITE_FUNCTION_CODES

    def is_diagnostic_function(self, function_code: int) -> bool:
        """True if the function code indicates diagnostic/discovery traffic."""
        return function_code in self.DIAGNOSTIC_FUNCTION_CODES

    def is_control_function(self, function_code: int) -> bool:
        """True if the function code indicates a control command."""
        return function_code in self.CONTROL_FUNCTION_CODES

    def _classify_risk(self, function_code: int) -> tuple[bool, bool, bool, Optional[str]]:
        """Classify function code for risk flags.

        Returns:
            (is_write, is_diagnostic, is_control, risk_note)
        """
        is_write = self.is_write_function(function_code)
        is_diag = self.is_diagnostic_function(function_code)
        is_ctrl = self.is_control_function(function_code)

        risk_note = None
        if is_ctrl:
            risk_note = "Control command — operational impact risk"
        elif is_write:
            risk_note = "Write operation — data modification risk"
        elif is_diag:
            risk_note = "Diagnostic/discovery — information disclosure risk"

        return is_write, is_diag, is_ctrl, risk_note

    def _build_frame(
        self,
        packet: PacketMetadata,
        function_code: Optional[int],
        payload: dict,
        is_request: bool = True,
        is_exception: bool = False,
        message_type: Optional[str] = None,
    ) -> ProtocolFrame:
        """Build a ProtocolFrame with shared classification logic."""
        is_write, is_diag, is_ctrl, risk_note = (False, False, False, None)
        func_name = None

        if function_code is not None:
            is_write, is_diag, is_ctrl, risk_note = self._classify_risk(function_code)
            func_name = self.get_function_description(function_code)

        slug = (self.PROTOCOL_SLUG or self.PROTOCOL_NAME.lower().replace(" ", "").replace("/", "")).lower()

        return ProtocolFrame(
            timestamp=packet.timestamp,
            src_ip=packet.src_ip or "",
            dst_ip=packet.dst_ip or "",
            src_port=packet.src_port or 0,
            dst_port=packet.dst_port or 0,
            protocol=self.PROTOCOL_NAME,
            protocol_slug=slug,
            function_code=function_code,
            function_name=func_name,
            payload=payload,
            is_request=is_request,
            is_exception=is_exception,
            message_type=message_type,
            raw_bytes=packet.payload,
            packet_number=packet.packet_number,
            pcap_file=packet.pcap_file,
            is_write_operation=is_write,
            is_diagnostic=is_diag,
            is_control_command=is_ctrl,
            risk_note=risk_note,
        )
