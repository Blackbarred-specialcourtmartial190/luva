"""End-to-end pipeline tests with a minimal Scapy-generated capture."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

pytest.importorskip("scapy")
from scapy.all import IP, Raw, TCP, wrpcap  # noqa: E402

from luva.core.config import AnalysisConfig, AnalysisMode
from luva.core.pipeline import AnalysisPipeline


def _mbap(transaction_id: int, length: int, unit_id: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", transaction_id, 0, length, unit_id) + pdu


def test_pipeline_processes_modbus_in_pcap(tmp_path: Path) -> None:
    pdu = struct.pack(">BHH", 0x03, 100, 10)
    payload = _mbap(1, 1 + len(pdu), 1, pdu)
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=502) / Raw(load=payload)
    pcap = tmp_path / "modbus_one.pcap"
    wrpcap(str(pcap), [pkt])

    cfg = AnalysisConfig(input_files=[pcap], protocols=["modbus"], mode=AnalysisMode.FULL)
    result = AnalysisPipeline(cfg).run()

    assert result.metadata["total_packets"] == 1
    assert result.metadata.get("analysis_mode") == "full"
    assert len(result.flows) >= 1
    assert any(f.dst_port == 502 for f in result.flows)


def test_pipeline_processes_s7_on_port_102(tmp_path: Path) -> None:
    """Minimal S7 TPKT/COTP-style payload on TCP/102 produces an S7-tagged flow."""
    pdu = bytes.fromhex("0300001611e00000000600c1020100c2020102c0010a")
    pkt = IP(src="10.0.0.5", dst="10.0.0.6") / TCP(sport=40002, dport=102) / Raw(load=pdu)
    pcap = tmp_path / "s7_one.pcap"
    wrpcap(str(pcap), [pkt])

    cfg = AnalysisConfig(input_files=[pcap], protocols=["s7"], mode=AnalysisMode.FULL)
    result = AnalysisPipeline(cfg).run()

    assert result.metadata["total_packets"] == 1
    assert any(f.dst_port == 102 for f in result.flows)
    assert any(
        f.ics_protocol == "S7" or "S7" in f.ics_protocols_seen for f in result.flows
    )


def test_asset_only_skips_anomaly_rules(tmp_path: Path) -> None:
    pdu = struct.pack(">BHH", 0x03, 100, 10)
    payload = _mbap(1, 1 + len(pdu), 1, pdu)
    pkt = IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=40001, dport=502) / Raw(load=payload)
    pcap = tmp_path / "modbus_asset.pcap"
    wrpcap(str(pcap), [pkt])

    cfg = AnalysisConfig(
        input_files=[pcap],
        protocols=["modbus"],
        mode=AnalysisMode.ASSET_ONLY,
    )
    result = AnalysisPipeline(cfg).run()
    assert result.anomalies == []
    assert len(result.assets) >= 1
