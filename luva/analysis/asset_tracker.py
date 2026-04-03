"""Asset tracker — passive inventory, role inference, and risk hints."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Optional

from luva.engine.pcap_reader import PacketMetadata
from luva.models.asset import Asset, DeviceRole
from luva.parsers.base import ProtocolFrame
from luva.utils.oui_lookup import lookup_oui
from luva.utils.port_registry import lookup_port

logger = logging.getLogger(__name__)


class AssetTracker:
    """Discover and update assets from packet metadata and parsed ICS frames.

    - Creates/updates devices by IP
    - Maps MAC → vendor via OUI
    - Infers coarse device roles
    - Accumulates heuristic risk factors
    """

    def __init__(self):
        self._assets: dict[str, Asset] = {}  # IP → Asset
        self._mac_ip_map: dict[str, set[str]] = defaultdict(set)  # MAC → {IP, ...}
        self._protocol_users: dict[str, set[str]] = defaultdict(set)  # proto → {IP, ...}

    def process_packet(self, packet: PacketMetadata) -> None:
        """Update assets from one packet's metadata."""
        if packet.src_ip:
            asset = self._get_or_create(packet.src_ip)
            asset.update_seen(packet.timestamp)
            asset.packet_count += 1
            asset.bytes_total += packet.length

            if packet.src_mac:
                asset.mac_address = packet.src_mac
                self._mac_ip_map[packet.src_mac].add(packet.src_ip)
                if not asset.vendor:
                    asset.vendor = lookup_oui(packet.src_mac)

            if packet.src_port:
                asset.add_port(packet.src_port)
            if packet.dst_ip:
                asset.add_partner(packet.dst_ip)
                asset.initiated_connections += 1

        if packet.dst_ip:
            asset = self._get_or_create(packet.dst_ip)
            asset.update_seen(packet.timestamp)

            if packet.dst_mac:
                asset.mac_address = packet.dst_mac
                self._mac_ip_map[packet.dst_mac].add(packet.dst_ip)
                if not asset.vendor:
                    asset.vendor = lookup_oui(packet.dst_mac)

            if packet.dst_port:
                asset.add_port(packet.dst_port)
            if packet.src_ip:
                asset.add_partner(packet.src_ip)
                asset.received_connections += 1

    def process_frame(self, frame: ProtocolFrame) -> None:
        """Enrich assets using a parsed protocol frame."""
        for ip in (frame.src_ip, frame.dst_ip):
            if ip:
                asset = self._get_or_create(ip)
                asset.add_protocol(frame.protocol)
                self._protocol_users[frame.protocol].add(ip)

        if frame.protocol == "Modbus" and "unit_id" in frame.payload:
            unit_id = frame.payload["unit_id"]
            if frame.dst_ip:
                dst_asset = self._get_or_create(frame.dst_ip)
                dst_asset.modbus_unit_ids.add(unit_id)

        if frame.protocol == "S7":
            if "s7_function_code" in frame.payload:
                if frame.payload.get("s7_function_code") == 0xF0:
                    if frame.dst_ip:
                        dst_asset = self._get_or_create(frame.dst_ip)
                        if "rack" in frame.payload:
                            dst_asset.plc_rack = frame.payload["rack"]
                        if "slot" in frame.payload:
                            dst_asset.plc_slot = frame.payload["slot"]

        if frame.protocol == "DNP3":
            if "dl_destination" in frame.payload:
                if frame.dst_ip:
                    dst_asset = self._get_or_create(frame.dst_ip)
                    dst_asset.dnp3_address = frame.payload["dl_destination"]
            if "dl_source" in frame.payload:
                if frame.src_ip:
                    src_asset = self._get_or_create(frame.src_ip)
                    src_asset.dnp3_address = frame.payload["dl_source"]

        if frame.is_write_operation or frame.is_control_command:
            if frame.src_ip:
                src_asset = self._get_or_create(frame.src_ip)
                if frame.is_control_command:
                    src_asset.add_risk_factor(
                        f"Sent control command: {frame.function_name}",
                        2.0
                    )
                elif frame.is_write_operation:
                    src_asset.add_risk_factor(
                        f"Performed write operation: {frame.function_name}",
                        1.0
                    )

    def infer_roles(self) -> None:
        """Assign DeviceRole heuristics from accumulated fields."""
        for ip, asset in self._assets.items():
            role = self._infer_single_role(asset)
            asset.role = role

    def _infer_single_role(self, asset: Asset) -> DeviceRole:
        """Infer role for one asset."""
        protocols = asset.protocols_seen
        ports = asset.open_ports

        plc_indicators = 0
        if "Modbus" in protocols and asset.modbus_unit_ids:
            plc_indicators += 2
        if "S7" in protocols and (asset.plc_slot is not None or asset.plc_rack is not None):
            plc_indicators += 3
        if 502 in ports or 102 in ports:
            plc_indicators += 1
        if asset.received_connections > asset.initiated_connections * 2:
            plc_indicators += 1

        if plc_indicators >= 3:
            return DeviceRole.PLC

        if "DNP3" in protocols and asset.dnp3_address is not None:
            if asset.received_connections > asset.initiated_connections:
                return DeviceRole.RTU

        hmi_indicators = 0
        if asset.initiated_connections > asset.received_connections:
            hmi_indicators += 1
        if len(asset.communication_partners) >= 3:
            hmi_indicators += 1
        if any(p in protocols for p in ("Modbus", "S7", "OPC UA", "BACnet", "MQTT")):
            hmi_indicators += 1
        if 80 in ports or 443 in ports:
            hmi_indicators += 1

        if hmi_indicators >= 3:
            return DeviceRole.HMI

        eng_indicators = 0
        if any(p in protocols for p in ("S7", "EtherNet/IP")):
            eng_indicators += 1
        if len(asset.communication_partners) >= 5:
            eng_indicators += 1
        if asset.initiated_connections > asset.received_connections * 3:
            eng_indicators += 2

        if eng_indicators >= 3:
            return DeviceRole.ENG_STATION

        if 1433 in ports or 3306 in ports:
            if "OPC UA" in protocols or len(asset.communication_partners) >= 5:
                return DeviceRole.HISTORIAN

        if "IEC 104" in protocols and asset.initiated_connections > asset.received_connections:
            return DeviceRole.SCADA_SERVER

        if len(protocols) >= 3:
            return DeviceRole.GATEWAY

        ics_protocols = {
            "Modbus",
            "S7",
            "DNP3",
            "OPC UA",
            "EtherNet/IP",
            "IEC 104",
            "BACnet",
            "MQTT",
            "SNMP",
        }
        if protocols & ics_protocols:
            if asset.received_connections > asset.initiated_connections:
                return DeviceRole.PLC
            return DeviceRole.HMI

        return DeviceRole.UNKNOWN

    def calculate_risk_scores(self) -> None:
        """Apply port/protocol heuristics to risk_score and risk_factors."""
        for ip, asset in self._assets.items():
            unsafe_ports = {23, 21, 5900, 3389}
            for port in asset.open_ports & unsafe_ports:
                port_info = lookup_port(port)
                name = port_info.service_name if port_info else f"port {port}"
                asset.add_risk_factor(f"Insecure cleartext or risky service: {name}", 1.5)

            if len(asset.communication_partners) > 20:
                asset.add_risk_factor(
                    f"High number of communication partners: {len(asset.communication_partners)}",
                    1.0
                )

            ics_protos = asset.protocols_seen & {
                "Modbus",
                "S7",
                "DNP3",
                "OPC UA",
                "EtherNet/IP",
                "IEC 104",
                "BACnet",
                "MQTT",
                "SNMP",
            }
            if len(ics_protos) >= 3:
                asset.add_risk_factor(
                    f"Multiple ICS protocols on one host: {', '.join(sorted(ics_protos))}",
                    0.5
                )

    def _get_or_create(self, ip: str) -> Asset:
        """Get or create asset for IP."""
        if ip not in self._assets:
            self._assets[ip] = Asset(ip_address=ip)
        return self._assets[ip]

    def get_asset(self, ip: str) -> Optional[Asset]:
        """Return asset by IP if known."""
        return self._assets.get(ip)

    def get_all_assets(self) -> list[Asset]:
        """All discovered assets."""
        return list(self._assets.values())

    @property
    def asset_count(self) -> int:
        return len(self._assets)

    @property
    def stats(self) -> dict:
        """Aggregate asset statistics."""
        role_counts: dict[str, int] = defaultdict(int)
        for asset in self._assets.values():
            role_counts[asset.role.name] += 1

        protocol_counts = defaultdict(int)
        for proto, ips in self._protocol_users.items():
            protocol_counts[proto] = len(ips)

        return {
            "total_assets": self.asset_count,
            "role_distribution": dict(role_counts),
            "protocol_user_counts": dict(protocol_counts),
            "assets_with_risk": sum(1 for a in self._assets.values() if a.risk_score > 0),
        }
