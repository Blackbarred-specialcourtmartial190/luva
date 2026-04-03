"""Anomaly-referenced PCAP subset export."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("scapy")
from scapy.all import IP, Raw, TCP, wrpcap  # noqa: E402

from luva.core.config import AnomalyCategory, Severity
from luva.models.event import AnomalyEvent
from luva.output.anomaly_pcap_exporter import write_anomaly_subset_pcap


def test_write_anomaly_subset_extracts_packet(tmp_path: Path) -> None:
    pcap = tmp_path / "one.pcap"
    pkt = IP(src="10.1.1.1", dst="10.1.1.2") / TCP(sport=1111, dport=2222) / Raw(b"hello")
    wrpcap(str(pcap), [pkt])

    ev = AnomalyEvent(
        severity=Severity.LOW,
        category=AnomalyCategory.NETWORK,
        rule_id="x",
        rule_name="x",
        description="test",
        packet_number=1,
        pcap_file=pcap.name,
    )
    out = tmp_path / "sub.pcap"
    n = write_anomaly_subset_pcap([pcap], [ev], out)
    assert n == 1
    assert out.is_file() and out.stat().st_size > 24
