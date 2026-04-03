"""EKS taxonomy and inference tests."""

from __future__ import annotations

from luva.analysis.eks_report import build_eks_section, infer_eks_tags
from luva.models.asset import Asset, DeviceRole
from luva.models.eks_taxonomy import ALL_EKS_COMPONENTS


def test_catalog_covers_core_eks_roles() -> None:
    ids = {c.id for c in ALL_EKS_COMPONENTS}
    assert "plc_pac" in ids
    assert "hmi_station" in ids
    assert "scada_server" in ids
    assert "physical_process" in ids
    assert "industrial_dmz" in ids


def test_infer_plc_from_role() -> None:
    a = Asset(ip_address="10.0.0.1", role=DeviceRole.PLC)
    assert "plc_pac" in infer_eks_tags(a)


def test_infer_remote_access_from_ports() -> None:
    a = Asset(ip_address="10.0.0.2", role=DeviceRole.UNKNOWN, open_ports={3389})
    assert "remote_access" in infer_eks_tags(a)


def test_build_eks_section_counts() -> None:
    assets = [
        Asset(ip_address="10.0.0.1", role=DeviceRole.PLC),
        Asset(ip_address="10.0.0.2", role=DeviceRole.HMI),
    ]
    sec = build_eks_section(assets)
    assert sec["taxonomy_version"] == "1.0"
    assert len(sec["components_catalog"]) == len(ALL_EKS_COMPONENTS)
    assert "plc_pac" in sec["observed"]["by_component_id"]
    assert "purdue_model" in sec and "levels" in sec["purdue_model"]
    assert "principles" in sec["segmentation"]
    inv = sec["hosts_inventory"]
    assert len(inv) == 2
    assert inv[0]["ip_address"] == "10.0.0.1"
    assert inv[1]["ip_address"] == "10.0.0.2"
    assert "plc_pac" in inv[0]["eks_components"]
    assert any("plc_pac" in line for line in inv[0]["eks_tags_detailed"])
