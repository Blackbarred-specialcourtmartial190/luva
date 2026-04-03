"""ICS / EKS (Industrial Control Systems) component taxonomy and Purdue / ISA-95 reference.

Passive PCAP analysis cannot prove every component type; the catalog lists the full EKS
scope for reporting and gap analysis. Inferred tags per host are best-effort heuristics.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EKSComponentDefinition:
    """One logical EKS/ICS component type."""

    id: str
    name: str
    category: str
    purdue_levels: tuple[str, ...]
    description: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "purdue_isa95_levels": list(self.purdue_levels),
            "description": self.description,
        }


# Full EKS component catalog (IEC 62443 / ISA-95 / NIST SP 800-82 aligned).
ALL_EKS_COMPONENTS: tuple[EKSComponentDefinition, ...] = (
    EKSComponentDefinition(
        "physical_process",
        "Physical process",
        "process",
        ("0",),
        "Physical equipment and phenomena under control — not visible on IP/Ethernet captures; "
        "included so reports cover the full EKS stack from field to enterprise.",
    ),
    EKSComponentDefinition(
        "field_device",
        "Field device",
        "field",
        ("0",),
        "Sensors, actuators, analyzers, and final control elements on fieldbuses; IP visibility is rare unless bridged.",
    ),
    EKSComponentDefinition(
        "smart_field_instrument",
        "Smart field instrument",
        "field",
        ("0", "1"),
        "Intelligent instruments with embedded Ethernet (e.g. industrial Ethernet-APL, some Profinet devices).",
    ),
    EKSComponentDefinition(
        "remote_io",
        "Remote I/O",
        "control",
        ("1",),
        "Distributed I/O, marshalling cabinets, and I/O slices connected to a controller.",
    ),
    EKSComponentDefinition(
        "plc_pac",
        "PLC / PAC",
        "control",
        ("1",),
        "Programmable logic controllers and programmable automation controllers executing real-time control.",
    ),
    EKSComponentDefinition(
        "rtu",
        "RTU",
        "control",
        ("1", "2"),
        "Remote terminal units for telemetry and supervisory I/O toward a SCADA/DCS master.",
    ),
    EKSComponentDefinition(
        "dcs_controller",
        "DCS controller",
        "control",
        ("1", "2"),
        "Distributed control system controller / loop hosting; often indistinguishable from PLC in passive L3 view.",
    ),
    EKSComponentDefinition(
        "sis_safety_controller",
        "SIS / safety controller",
        "control",
        ("1",),
        "Safety instrumented system logic solver; should be segregated; inference from traffic alone is weak.",
    ),
    EKSComponentDefinition(
        "hmi_station",
        "HMI",
        "supervisory",
        ("2",),
        "Operator visualization: panels, SCADA clients, and local HMIs for process supervision.",
    ),
    EKSComponentDefinition(
        "scada_server",
        "SCADA server",
        "supervisory",
        ("2", "3"),
        "Tag servers, scan engines, alarm/event servers, and supervisory applications.",
    ),
    EKSComponentDefinition(
        "batch_engine",
        "Batch / sequence engine",
        "supervisory",
        ("2",),
        "Recipe and batch execution layer when present in the architecture.",
    ),
    EKSComponentDefinition(
        "historian",
        "Historian",
        "operations",
        ("3",),
        "Time-series and event archival for operations, reporting, and compliance.",
    ),
    EKSComponentDefinition(
        "mes_connector",
        "MES / plant IT interface",
        "operations",
        ("3",),
        "Manufacturing execution and plant-business integration touching the OT boundary.",
    ),
    EKSComponentDefinition(
        "engineering_workstation",
        "Engineering workstation (EWS)",
        "operations",
        ("3",),
        "Programming, commissioning, and maintenance tools for PLCs, DCS, drives, and safety.",
    ),
    EKSComponentDefinition(
        "operator_client",
        "Operator client / thin client",
        "supervisory",
        ("2", "3"),
        "General-purpose PCs used as SCADA/HMI clients distinct from dedicated panel hardware.",
    ),
    EKSComponentDefinition(
        "protocol_gateway",
        "Protocol gateway",
        "boundary",
        ("2", "3"),
        "Translates between field protocols (Modbus, DNP3, OPC, serial bridges) across segments.",
    ),
    EKSComponentDefinition(
        "iiot_edge_mqtt",
        "IIoT / MQTT edge",
        "boundary",
        ("2", "3", "4"),
        "MQTT brokers, lightweight pub/sub, and cloud/edge connectors common in IIoT architectures.",
    ),
    EKSComponentDefinition(
        "industrial_dmz",
        "Industrial DMZ",
        "security",
        ("3.5",),
        "Demilitarized zone between plant operations and enterprise IT — logical construct; "
        "rarely a single IP in PCAP but listed for segmentation design reference.",
    ),
    EKSComponentDefinition(
        "industrial_firewall",
        "Industrial firewall",
        "security",
        ("3",),
        "Zone-enforcing appliances (often L2/L3 transparent); seldom seen as an endpoint in user PCAPs.",
    ),
    EKSComponentDefinition(
        "network_switch_l2",
        "Managed L2 switch",
        "network",
        ("1", "2", "3"),
        "Layer-2 switching fabric; typically invisible as a host in IP flow exports.",
    ),
    EKSComponentDefinition(
        "network_router_l3",
        "L3 router",
        "network",
        ("2", "3", "4"),
        "Inter-VLAN and inter-zone routing between Purdue levels.",
    ),
    EKSComponentDefinition(
        "wireless_gateway",
        "Wireless / IIoT gateway",
        "network",
        ("1", "2"),
        "WLAN access or wireless sensor/IIoT backhaul aggregation.",
    ),
    EKSComponentDefinition(
        "domain_identity",
        "Domain / identity services",
        "enterprise_bridge",
        ("3", "4", "5"),
        "Active Directory, LDAP, Kerberos, and related identity when observed at the IT/OT boundary.",
    ),
    EKSComponentDefinition(
        "database_server",
        "Database server",
        "operations",
        ("3",),
        "SQL and embedded databases backing SCADA, historians, and MES connectors.",
    ),
    EKSComponentDefinition(
        "ntp_time",
        "Time synchronization (NTP/SNTP)",
        "infrastructure",
        ("1", "2", "3"),
        "Clock sync for event ordering, SOE, and cryptographic validity across IACS.",
    ),
    EKSComponentDefinition(
        "remote_access",
        "Remote access",
        "security",
        ("3", "4", "5"),
        "VPN, RDP, VNC, and similar paths used for vendor or remote maintenance — high review priority.",
    ),
    EKSComponentDefinition(
        "snmp_management",
        "SNMP / NMS",
        "operations",
        ("3",),
        "Network and device monitoring via SNMP managers and agents.",
    ),
    EKSComponentDefinition(
        "building_automation",
        "Building automation (BMS)",
        "building",
        ("2", "3"),
        "BACnet and related BMS that may interface with plant utilities and perimeter systems.",
    ),
    EKSComponentDefinition(
        "ups_electrical_monitoring",
        "Electrical / UPS monitoring",
        "infrastructure",
        ("1", "2"),
        "Power monitoring and UPS gateways when they appear as IP endpoints.",
    ),
)


def components_catalog_dicts() -> list[dict]:
    """Serializable full EKS catalog for JSON/HTML."""
    return [c.to_dict() for c in ALL_EKS_COMPONENTS]


def purdue_reference() -> dict:
    """ISA-95 / Purdue-style level reference for reports."""
    return {
        "model_name": "Purdue Enterprise Reference Architecture (PERA) / ISA-95 alignment",
        "levels": [
            {
                "level": "5",
                "name": "Enterprise",
                "summary": "Corporate WAN, business systems, and internet-facing services.",
            },
            {
                "level": "4",
                "name": "Site business / logistics",
                "summary": "Site ERP, mail, and business LAN; should not directly touch real-time control.",
            },
            {
                "level": "3",
                "name": "Operations / site manufacturing",
                "summary": "Historians, MES interfaces, engineering stations, wide-area SCADA, and OT DMZ entry.",
            },
            {
                "level": "2",
                "name": "Area / cell supervision",
                "summary": "HMIs, supervisory SCADA, batch visibility, alarms, and area coordination.",
            },
            {
                "level": "1",
                "name": "Basic (real-time) control",
                "summary": "PLCs, RTUs, DCS controllers, drives, and safety controllers executing control loops.",
            },
            {
                "level": "0",
                "name": "Process",
                "summary": "Physical process, sensors, actuators, and field wiring — below IP in many plants.",
            },
        ],
        "conduits_note": (
            "IEC 62443 describes conduits (controlled communication paths) between zones. "
            "A single TCP flow in a PCAP may cross several logical zones; correlate with drawings."
        ),
    }


def segmentation_guidance() -> dict:
    """Static OT segmentation principles for analyst-facing reports."""
    return {
        "title": "OT network segmentation (design principles)",
        "principles": [
            "Separate enterprise (Levels 4–5) from operations (Level 3) with a DMZ and industrial firewalls; "
            "deny direct routing from the internet to PLCs.",
            "Keep real-time control (Level 1) reachable only from supervision (Level 2) and authorized "
            "engineering paths — not from business VLANs.",
            "Use unidirectional gateways or data diodes for high-assurance export of historian or "
            "mirror data to IT where required.",
            "Restrict remote access (VPN, jump hosts) to explicit jump servers; log and segment vendor access.",
            "Apply conduit rules per IEC 62443: document who may initiate sessions, which protocols are allowed, "
            "and monitor for policy violations in captures.",
            "Time sync (NTP) and identity (AD) at the boundary should be hardened; avoid flat networks "
            "spanning Purdue levels.",
        ],
        "references": [
            "ISA/IEC 62443 (industrial automation and control systems security)",
            "ISA-95 / IEC 62264 (enterprise–control system integration)",
            "NIST SP 800-82 Rev. 3 (Guide to OT Security)",
            "NERC CIP (where electric bulk electric system applies)",
        ],
    }
