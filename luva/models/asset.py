"""Asset model — representation of a discovered network endpoint."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class DeviceRole(str, Enum):
    """High-level device role classification."""
    PLC = "Programmable Logic Controller"
    HMI = "Human Machine Interface"
    HISTORIAN = "Data Historian"
    ENG_STATION = "Engineering Station"
    RTU = "Remote Terminal Unit"
    GATEWAY = "Protocol Gateway"
    SWITCH = "Network Switch"
    SCADA_SERVER = "SCADA Server"
    IO_MODULE = "I/O Module"
    UNKNOWN = "Unknown"


@dataclass
class Asset:
    """Everything we infer about one discovered device."""

    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None  # from OUI lookup when available
    role: DeviceRole = DeviceRole.UNKNOWN
    protocols_seen: set[str] = field(default_factory=set)
    open_ports: set[int] = field(default_factory=set)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    packet_count: int = 0
    bytes_total: int = 0

    # ICS-specific fields
    plc_slot: Optional[int] = None       # S7 rack/slot
    plc_rack: Optional[int] = None       # S7 rack
    modbus_unit_ids: set[int] = field(default_factory=set)
    dnp3_address: Optional[int] = None
    firmware_hints: list[str] = field(default_factory=list)

    # Communication stats
    communication_partners: set[str] = field(default_factory=set)
    initiated_connections: int = 0
    received_connections: int = 0

    # Risk scoring
    risk_score: float = 0.0
    risk_factors: list[str] = field(default_factory=list)

    def update_seen(self, timestamp: datetime) -> None:
        """Update first/last seen timestamps."""
        if self.first_seen is None or timestamp < self.first_seen:
            self.first_seen = timestamp
        if self.last_seen is None or timestamp > self.last_seen:
            self.last_seen = timestamp

    def add_protocol(self, protocol: str) -> None:
        """Record a protocol observed for this asset."""
        self.protocols_seen.add(protocol)

    def add_port(self, port: int) -> None:
        """Record an open port."""
        self.open_ports.add(port)

    def add_partner(self, partner_ip: str) -> None:
        """Record a peer IP."""
        self.communication_partners.add(partner_ip)

    def add_risk_factor(self, factor: str, score_delta: float) -> None:
        """Append a risk factor and bump score (capped)."""
        if factor not in self.risk_factors:
            self.risk_factors.append(factor)
            self.risk_score = min(10.0, self.risk_score + score_delta)

    @property
    def active_duration(self) -> float:
        """Seconds between first and last seen."""
        if self.first_seen and self.last_seen:
            return (self.last_seen - self.first_seen).total_seconds()
        return 0.0

    def to_dict(self) -> dict:
        """JSON-serializable dict."""
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "role": self.role.value if self.role else "Unknown",
            "protocols_seen": sorted(self.protocols_seen),
            "open_ports": sorted(self.open_ports),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "packet_count": self.packet_count,
            "bytes_total": self.bytes_total,
            "modbus_unit_ids": sorted(self.modbus_unit_ids) if self.modbus_unit_ids else [],
            "plc_rack": self.plc_rack,
            "plc_slot": self.plc_slot,
            "dnp3_address": self.dnp3_address,
            "firmware_hints": self.firmware_hints,
            "communication_partners": sorted(self.communication_partners),
            "initiated_connections": self.initiated_connections,
            "received_connections": self.received_connections,
            "risk_score": round(self.risk_score, 2),
            "risk_factors": self.risk_factors,
        }
