"""ICS-oriented port registry — map well-known ports to services and risk hints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class PortInfo:
    """Metadata for a single port."""
    port: int
    protocol: str
    service_name: str
    transport: str  # "tcp", "udp", "both"
    description: str
    is_ics: bool = True
    risk_level: str = "normal"  # normal, elevated, critical


# Common OT/IT ports used for passive classification
ICS_PORT_REGISTRY: dict[int, PortInfo] = {
    # === Modbus ===
    502: PortInfo(502, "modbus", "Modbus TCP", "tcp",
                  "Modbus TCP/IP industrial fieldbus", True, "elevated"),

    # === Siemens S7 ===
    102: PortInfo(102, "s7", "Siemens S7 (COTP/TPKT)", "tcp",
                  "Siemens S7 PLC communication over COTP/TPKT", True, "elevated"),

    # === DNP3 ===
    20000: PortInfo(20000, "dnp3", "DNP3", "both",
                    "Distributed Network Protocol 3 — SCADA telecontrol", True, "elevated"),

    # === OPC UA ===
    4840: PortInfo(4840, "opcua", "OPC UA Binary", "tcp",
                   "OPC Unified Architecture binary protocol", True, "elevated"),

    # === EtherNet/IP ===
    44818: PortInfo(44818, "enip", "EtherNet/IP (TCP)", "tcp",
                    "EtherNet/IP — connected CIP messaging", True, "elevated"),
    2222: PortInfo(2222, "enip", "EtherNet/IP (UDP)", "udp",
                   "EtherNet/IP — connectionless CIP messaging", True, "elevated"),

    # === IEC 60870-5-104 ===
    2404: PortInfo(2404, "iec104", "IEC 60870-5-104", "tcp",
                   "IEC 104 SCADA telecontrol (TCP)", True, "elevated"),

    # === BACnet ===
    47808: PortInfo(47808, "bacnet", "BACnet/IP", "udp",
                    "Building Automation and Control Networks", True, "normal"),

    # === Other ICS ===
    9600: PortInfo(9600, "omron_fins", "Omron FINS", "both",
                   "Omron Factory Interface Network Service", True, "elevated"),
    18245: PortInfo(18245, "ge_srtp", "GE SRTP", "tcp",
                    "GE Service Request Transport Protocol", True, "elevated"),
    18246: PortInfo(18246, "ge_srtp", "GE SRTP (alt)", "tcp",
                    "GE SRTP alternate port", True, "elevated"),
    1089: PortInfo(1089, "ff_hsb", "Foundation Fieldbus HSE", "tcp",
                   "Foundation Fieldbus High Speed Ethernet", True, "normal"),
    34962: PortInfo(34962, "profinet", "PROFINET RT", "udp",
                    "PROFINET real-time messaging", True, "elevated"),
    34963: PortInfo(34963, "profinet", "PROFINET RT-DCP", "udp",
                    "PROFINET discovery and configuration", True, "elevated"),
    34964: PortInfo(34964, "profinet", "PROFINET Context Manager", "tcp",
                    "PROFINET context manager", True, "elevated"),

    # === IT / OT gateway ports ===
    22: PortInfo(22, "ssh", "SSH", "tcp", "Secure Shell", False, "normal"),
    23: PortInfo(23, "telnet", "Telnet", "tcp",
                 "Telnet — cleartext remote access", False, "critical"),
    80: PortInfo(80, "http", "HTTP", "tcp", "HTTP web service", False, "normal"),
    443: PortInfo(443, "https", "HTTPS", "tcp", "HTTPS web service", False, "normal"),
    161: PortInfo(161, "snmp", "SNMP", "udp",
                  "Simple Network Management Protocol", False, "normal"),
    3389: PortInfo(3389, "rdp", "RDP", "tcp",
                   "Remote Desktop Protocol", False, "elevated"),
    5900: PortInfo(5900, "vnc", "VNC", "tcp",
                   "Virtual Network Computing remote desktop", False, "elevated"),
    1433: PortInfo(1433, "mssql", "MS SQL Server", "tcp",
                   "Microsoft SQL Server (often historian/back-end)", False, "elevated"),
    3306: PortInfo(3306, "mysql", "MySQL", "tcp",
                   "MySQL database server", False, "elevated"),
}


def lookup_port(port: int) -> Optional[PortInfo]:
    """Return registry entry for port, if any."""
    return ICS_PORT_REGISTRY.get(port)


def is_ics_port(port: int) -> bool:
    """True if the port is tagged as ICS-related in the registry."""
    info = ICS_PORT_REGISTRY.get(port)
    return info.is_ics if info else False


def get_protocol_by_port(port: int) -> Optional[str]:
    """Protocol slug for a port, if registered."""
    info = ICS_PORT_REGISTRY.get(port)
    return info.protocol if info else None


def get_all_ics_ports() -> list[int]:
    """All ports marked as ICS in the registry."""
    return [p for p, info in ICS_PORT_REGISTRY.items() if info.is_ics]


def get_risk_ports() -> dict[str, list[int]]:
    """Ports grouped by configured risk_level."""
    result: dict[str, list[int]] = {"normal": [], "elevated": [], "critical": []}
    for port, info in ICS_PORT_REGISTRY.items():
        result[info.risk_level].append(port)
    return result
