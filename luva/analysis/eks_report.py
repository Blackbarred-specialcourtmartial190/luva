"""Build EKS (ICS) component reporting: inferred tags per asset and reference taxonomy."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from luva.models.eks_taxonomy import (
    ALL_EKS_COMPONENTS,
    components_catalog_dicts,
    purdue_reference,
    segmentation_guidance,
)

_EKS_ID_TO_NAME: dict[str, str] = {c.id: c.name for c in ALL_EKS_COMPONENTS}

if TYPE_CHECKING:
    from luva.models.asset import Asset


def infer_eks_tags(asset: Asset) -> list[str]:
    """Best-effort EKS component tags from role, ports, and protocols (passive heuristics)."""
    from luva.models.asset import DeviceRole

    tags: set[str] = set()
    role = asset.role
    ports = asset.open_ports
    protos = asset.protocols_seen

    role_primary: dict[DeviceRole, tuple[str, ...]] = {
        DeviceRole.PLC: ("plc_pac",),
        DeviceRole.HMI: ("hmi_station", "operator_client"),
        DeviceRole.HISTORIAN: ("historian",),
        DeviceRole.ENG_STATION: ("engineering_workstation",),
        DeviceRole.RTU: ("rtu",),
        DeviceRole.GATEWAY: ("protocol_gateway",),
        DeviceRole.SWITCH: ("network_switch_l2",),
        DeviceRole.SCADA_SERVER: ("scada_server",),
        DeviceRole.IO_MODULE: ("remote_io",),
        DeviceRole.UNKNOWN: (),
    }
    tags.update(role_primary.get(role, ()))

    if "MQTT" in protos:
        tags.add("iiot_edge_mqtt")
    if "SNMP" in protos:
        tags.add("snmp_management")
    if "BACnet" in protos:
        tags.add("building_automation")

    if 502 in ports or 102 in ports:
        tags.add("plc_pac")
    if 20000 in ports:
        tags.add("rtu")
        if asset.initiated_connections > asset.received_connections:
            tags.add("scada_server")
    if 2404 in ports:
        tags.add("rtu")
        if asset.initiated_connections > asset.received_connections:
            tags.add("scada_server")
    if 44818 in ports:
        tags.add("plc_pac")
    if 4840 in ports:
        tags.add("scada_server")
        tags.add("operator_client")
    if 1883 in ports or 8883 in ports or 8884 in ports or 9001 in ports:
        tags.add("iiot_edge_mqtt")
    if 47808 in ports:
        tags.add("building_automation")
    if 161 in ports or 162 in ports:
        tags.add("snmp_management")
    if 1433 in ports or 3306 in ports or 5432 in ports:
        tags.add("database_server")
    if 123 in ports:
        tags.add("ntp_time")
    if 22 in ports or 3389 in ports or 5900 in ports:
        tags.add("remote_access")
    if 88 in ports or 389 in ports or 636 in ports:
        tags.add("domain_identity")

    if role == DeviceRole.UNKNOWN and not tags:
        if protos & {"Modbus", "S7", "DNP3", "OPC UA", "EtherNet/IP", "IEC 104"}:
            tags.add("plc_pac")

    return sorted(tags)


def _eks_tag_labels(tag_ids: list[str]) -> list[str]:
    """Human-readable lines: ``component_id — catalog name``."""
    return [f"{tid} — {_EKS_ID_TO_NAME.get(tid, tid)}" for tid in tag_ids]


def build_eks_section(assets: list[Asset]) -> dict:
    """Full `eks` block for JSON/HTML: catalog, Purdue text, segmentation, observed summary."""
    by_id: Counter[str] = Counter()
    tagged = 0
    hosts_inventory: list[dict] = []

    for a in sorted(assets, key=lambda x: (x.ip_address or "")):
        t = infer_eks_tags(a)
        if t:
            tagged += 1
        for x in t:
            by_id[x] += 1

        partners = sorted(a.communication_partners)
        hosts_inventory.append(
            {
                "ip_address": a.ip_address,
                "mac_address": a.mac_address,
                "hostname": a.hostname,
                "role": a.role.value if a.role else "Unknown",
                "vendor": a.vendor,
                "eks_components": t,
                "eks_tags_detailed": _eks_tag_labels(t),
                "protocols_seen": sorted(a.protocols_seen),
                "open_ports": sorted(a.open_ports),
                "first_seen": a.first_seen.isoformat() if a.first_seen else None,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                "packet_count": a.packet_count,
                "bytes_total": a.bytes_total,
                "initiated_connections": a.initiated_connections,
                "received_connections": a.received_connections,
                "communication_partners": partners,
                "communication_partners_count": len(partners),
                "risk_score": round(a.risk_score, 2),
                "risk_factors": list(a.risk_factors),
                "modbus_unit_ids": sorted(a.modbus_unit_ids) if a.modbus_unit_ids else [],
                "plc_rack": a.plc_rack,
                "plc_slot": a.plc_slot,
                "dnp3_address": a.dnp3_address,
                "firmware_hints": list(a.firmware_hints),
            },
        )

    catalog_ids = {c.id for c in ALL_EKS_COMPONENTS}
    observed_ids = set(by_id.keys())
    not_observed = sorted(catalog_ids - observed_ids)

    return {
        "taxonomy_version": "1.0",
        "scope_note": (
            "Industrial control system (ICS / EKS) component catalog lists the full logical stack from field to enterprise. "
            "Passive PCAPs only reveal IP-speaking endpoints; field devices, many switches, and firewalls "
            "often do not appear as hosts. Per-asset eks_components are heuristics — validate against plant documentation."
        ),
        "components_catalog": components_catalog_dicts(),
        "purdue_model": purdue_reference(),
        "segmentation": segmentation_guidance(),
        "observed": {
            "by_component_id": dict(sorted(by_id.items(), key=lambda kv: (-kv[1], kv[0]))),
            "assets_with_tags": tagged,
            "component_types_observed": len(observed_ids),
            "component_types_in_catalog": len(catalog_ids),
            "catalog_ids_not_observed_in_capture": not_observed,
        },
        "hosts_inventory": hosts_inventory,
        "hosts_inventory_note": (
            "One row per discovered IPv4 endpoint. EKS tags are passive heuristics (role, ports, protocols); "
            "cross-check with plant documentation and Purdue segmentation."
        ),
    }
