"""Smoke tests: minimal PCAP via Scapy, CLI exit code, Modbus MBAP parse."""

from __future__ import annotations

from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap

from ot_baseline.cli import run
from ot_baseline.parser.modbus_tcp import iter_modbus_requests_from_tcp_payload


def test_modbus_mbap_reads_fc3() -> None:
    # MBAP: tid=1 pid=0 len=6 (unit+5 pdu) unit=1 FC=3 + 4 dummy pdu bytes
    payload = bytes.fromhex("000100000006010300000001")
    out = list(iter_modbus_requests_from_tcp_payload(payload))
    assert len(out) == 1
    fc, cat = out[0]
    assert fc == 3
    assert cat == "read"


def test_cli_writes_reports(tmp_path: Path) -> None:
    # Single TCP packet 502 -> ephemeral with Modbus read holding registers
    sport, dport = 502, 49152
    payload = bytes.fromhex("0001000000060103000000010001".replace(" ", ""))
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=sport, dport=dport) / payload
    pcap = tmp_path / "t.pcap"
    wrpcap(str(pcap), [pkt])

    outdir = tmp_path / "out"
    code = run(["--pcap", str(pcap), "-o", str(outdir)])
    assert code == 0
    assert (outdir / "communication_map.json").is_file()
    assert (outdir / "protocol_distribution.json").is_file()
    assert (outdir / "traffic_profile.json").is_file()
    assert (outdir / "command_profile.json").is_file()
    assert (outdir / "summary.txt").is_file()
