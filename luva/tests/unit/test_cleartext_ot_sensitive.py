"""Tests for OT cleartext-sensitive payload heuristics."""

from __future__ import annotations

from datetime import datetime, timezone

from luva.analysis.cleartext_ot_sensitive import inspect_tcp_ot_cleartext, inspect_udp_ot_cleartext
from luva.analysis.deep_survey import DeepPacketSurvey
from luva.engine.pcap_reader import PacketMetadata


def _tcp_meta(
    payload: bytes,
    *,
    sport: int = 40000,
    dport: int = 502,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
) -> PacketMetadata:
    return PacketMetadata(
        packet_number=1,
        timestamp=datetime.now(timezone.utc),
        length=100,
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        transport="TCP",
        payload=payload,
        payload_length=len(payload),
    )


def test_modbus_write_detected_as_high() -> None:
    # MBAP + unit 1 + FC 6 (Write Single Register)
    pl = bytes.fromhex("000100000006010600000001")
    obs = inspect_tcp_ot_cleartext(_tcp_meta(pl), pl)
    cats = {o["category"] for o in obs}
    assert "modbus_tcp_cleartext" in cats
    mod = next(o for o in obs if o["category"] == "modbus_tcp_cleartext")
    assert mod["sensitivity"] == "HIGH"
    assert "evidence_preview_hex" in mod


def test_snmp_community_redacted() -> None:
    # SNMPv2c-style: SEQUENCE, version 0, OCTET STRING community "public"
    pl = bytes.fromhex(
        "302902010004067075626c6963a01c020458000000020100020100300e300c06082b060102010101000500"
    )
    meta = PacketMetadata(
        packet_number=1,
        timestamp=datetime.now(timezone.utc),
        length=60,
        src_ip="10.0.0.5",
        dst_ip="10.0.0.10",
        src_port=52341,
        dst_port=161,
        transport="UDP",
        payload=pl,
        payload_length=len(pl),
    )
    obs = inspect_udp_ot_cleartext(meta, pl)
    snmp = next(o for o in obs if o["category"] == "snmp_cleartext_community")
    assert "snmp_community_redacted" in snmp
    assert "public" not in snmp["snmp_community_redacted"]


def test_deep_survey_accumulates_ot_sensitive() -> None:
    pl = bytes.fromhex("000100000006010600000001")
    meta = _tcp_meta(pl)
    s = DeepPacketSurvey()
    s.process(meta)
    s.process(meta)
    d = s.to_dict()
    cot = d["cleartext_ot_sensitive"]
    assert cot["hits_by_category"].get("modbus_tcp_cleartext", 0) == 2
    assert len(cot["samples"]) == 1


def test_http_ot_token_in_cleartext() -> None:
    pl = b"GET /api/plc/status HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n"
    obs = inspect_tcp_ot_cleartext(_tcp_meta(pl, dport=80, sport=54321), pl)
    assert any(o["category"] == "http_cleartext_ot_context" for o in obs)
