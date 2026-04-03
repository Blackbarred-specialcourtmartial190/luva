"""Classify and export OT/ICS-relevant assets (protocols, ICS ports, field hints, roles)."""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from luva.analysis.eks_report import infer_eks_tags
from luva.models.asset import DeviceRole
from luva.utils.port_registry import ICS_PORT_REGISTRY

if TYPE_CHECKING:
    from luva.models.asset import Asset

# Parser PROTOCOL_NAME values that indicate industrial / OT traffic.
ICS_PROTOCOL_NAMES: frozenset[str] = frozenset(
    {
        "Modbus",
        "S7",
        "DNP3",
        "OPC UA",
        "IEC 104",
        "BACnet",
        "EtherNet/IP",
        "GE SRTP",
        "Omron FINS",
        "MQTT",
    },
)

# Inferred roles treated as OT endpoints (excludes UNKNOWN and SWITCH-only heuristics).
OT_DEVICE_ROLES: frozenset[DeviceRole] = frozenset(
    {
        DeviceRole.PLC,
        DeviceRole.HMI,
        DeviceRole.HISTORIAN,
        DeviceRole.ENG_STATION,
        DeviceRole.RTU,
        DeviceRole.GATEWAY,
        DeviceRole.SCADA_SERVER,
        DeviceRole.IO_MODULE,
    },
)


def collect_ot_signals(asset: Asset) -> list[str]:
    """Human-readable reasons this asset is treated as OT-relevant."""
    signals: list[str] = []

    for proto in sorted(asset.protocols_seen):
        if proto in ICS_PROTOCOL_NAMES:
            signals.append(f"ics_protocol:{proto}")

    for port in sorted(asset.open_ports):
        info = ICS_PORT_REGISTRY.get(port)
        if info and info.is_ics:
            signals.append(f"ics_port:{port}:{info.service_name}")

    if asset.modbus_unit_ids:
        signals.append("field_hint:modbus_unit_ids")
    if asset.plc_rack is not None or asset.plc_slot is not None:
        signals.append("field_hint:s7_rack_slot")
    if asset.dnp3_address is not None:
        signals.append("field_hint:dnp3_address")

    if asset.role in OT_DEVICE_ROLES:
        signals.append(f"inferred_role:{asset.role.name}")

    return signals


def is_ot_asset(asset: Asset) -> bool:
    return bool(collect_ot_signals(asset))


def build_ot_assets_export(assets: list[Asset]) -> list[dict]:
    """Rows for JSON/HTML/CSV: full asset dict plus OT classification fields."""
    rows: list[dict] = []
    for asset in assets:
        sigs = collect_ot_signals(asset)
        if not sigs:
            continue
        eks = infer_eks_tags(asset)
        base = asset.to_dict()
        base["eks_components"] = eks
        base["ot_signals"] = sigs
        base["ot_signals_summary"] = "; ".join(sigs)
        rows.append(base)

    def _ip_key(ip: str) -> tuple[int, int]:
        try:
            return (0, int(ipaddress.IPv4Address(ip)))
        except (ValueError, ipaddress.AddressValueError):
            return (1, 0)

    rows.sort(key=lambda r: _ip_key(str(r.get("ip_address") or "")))
    return rows
