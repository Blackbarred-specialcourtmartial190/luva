"""Heuristic detection of OT-relevant data in cleartext L7 payloads (passive PCAP context)."""

from __future__ import annotations

import re
from typing import Any, Optional

from luva.engine.pcap_reader import PacketMetadata
from luva.utils.port_registry import ICS_PORT_REGISTRY, lookup_port

_TLS_CLIENT_HELLO = re.compile(rb"^\x16[\x03][\x01\x02\x03\x04]")

# Modbus TCP function codes commonly seen (subset; 5/6/15/16 are write-family).
_MODBUS_FC: dict[int, str] = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    7: "Read Exception Status",
    8: "Diagnostics",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    20: "Read File Record",
    21: "Write File Record",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    43: "Read Device Identification",
}
_MODBUS_WRITE_FC = frozenset({5, 6, 15, 16, 22, 23})

_ICS_TCP_PORTS = frozenset(
    p
    for p, inf in ICS_PORT_REGISTRY.items()
    if inf.is_ics and inf.transport in ("tcp", "both")
)

_HTTP_OT_NEEDLE = re.compile(
    rb"(?i)(modbus|opc[\s_-]?ua|opcua|/plc|plc[/._]|dnp3|iec[\s_-]?104|s7comm|"
    rb"siemens|rockwell|allen[\s_-]?bradley|scada|historian|/hmi|hmi[/._]|"
    rb"mqtt|sparkplug|profinet|bacnet|iec[\s_-]?61850|goose|mms\b)",
)

_BER_MAX = 512


def _hex_preview(pl: bytes, n: int = 36) -> str:
    return pl[:n].hex()


def _tls_client_hello_pl(pl: bytes) -> bool:
    return bool(_TLS_CLIENT_HELLO.match(pl[:4]))


def _ber_read_length(data: bytes, idx: int) -> tuple[int, int]:
    if idx >= len(data):
        return 0, idx
    fb = data[idx]
    idx += 1
    if fb & 0x80:
        n = fb & 0x7F
        if n == 0 or idx + n > len(data):
            return 0, idx - 1
        length = int.from_bytes(data[idx : idx + n], "big")
        return length, idx + n
    return fb, idx


def _snmp_v1_v2c_community_redacted(pl: bytes) -> Optional[str]:
    """Extract SNMPv1/v2c community (redacted) from cleartext UDP payload."""
    if len(pl) < 12 or pl[0] != 0x30:
        return None
    outer_len, i = _ber_read_length(pl, 1)
    if outer_len <= 0 or i + outer_len > len(pl) or outer_len > _BER_MAX:
        return None
    end = i + outer_len
    if i + 3 > end or pl[i] != 0x02 or pl[i + 1] != 0x01:
        return None
    ver = pl[i + 2]
    if ver not in (0, 1, 2, 3):
        return None
    i += 3
    if i + 2 > end or pl[i] != 0x04:
        return None
    clen, j = _ber_read_length(pl, i + 1)
    if clen <= 0 or j + clen > end or clen > 64:
        return None
    raw = pl[j : j + clen]
    try:
        s = raw.decode("utf-8", errors="replace")
    except Exception:
        s = raw.hex()[:24]
    s = s.strip() or "*"
    if len(s) <= 2:
        return s[0] + "*"
    if len(s) <= 4:
        return s[0] + "**" + s[-1]
    return s[0] + "*" * min(8, len(s) - 2) + s[-1]


def _try_modbus_tcp(pl: bytes, meta: PacketMetadata) -> Optional[dict[str, Any]]:
    if meta.dst_port != 502 and meta.src_port != 502:
        return None
    if len(pl) < 8 or pl[2:4] != b"\x00\x00":
        return None
    pdu_len = int.from_bytes(pl[4:6], "big")
    if pdu_len < 2 or pdu_len > 260:
        return None
    unit = pl[6]
    fc = pl[7]
    if fc not in _MODBUS_FC:
        return None
    fc_name = _MODBUS_FC[fc]
    write = fc in _MODBUS_WRITE_FC
    sens = "HIGH" if write else "MEDIUM"
    summ = (
        f"Modbus TCP PDU in cleartext (unit {unit}, FC {fc} {fc_name})"
        + (" — write-family function" if write else "")
    )
    return {
        "category": "modbus_tcp_cleartext",
        "sensitivity": sens,
        "summary": summ,
        "evidence_preview_hex": _hex_preview(pl),
        "dedupe_key": f"mb{fc}",
    }


def _try_modbus_port_unknown(pl: bytes, meta: PacketMetadata) -> Optional[dict[str, Any]]:
    if meta.dst_port != 502 and meta.src_port != 502:
        return None
    if len(pl) < 4:
        return None
    if pl[2:4] == b"\x00\x00" and len(pl) >= 8 and pl[7] in _MODBUS_FC:
        return None
    return {
        "category": "modbus_port_cleartext_non_mbap",
        "sensitivity": "MEDIUM",
        "summary": "Non-MBAP cleartext payload on TCP/502 (Modbus port) — may be fragmented or tunneled traffic",
        "evidence_preview_hex": _hex_preview(pl),
        "dedupe_key": "502unk",
    }


def _try_iec104(pl: bytes, meta: PacketMetadata) -> Optional[dict[str, Any]]:
    if len(pl) < 6 or pl[0] != 0x68:
        return None
    apdu_len = pl[1]
    if apdu_len < 4 or apdu_len > 253:
        return None
    on_port = meta.dst_port == 2404 or meta.src_port == 2404
    port_note = " on IEC-104 TCP port" if on_port else " (APCI-shaped frame; validate port and context)"
    sens = "HIGH" if on_port else "MEDIUM"
    return {
        "category": "iec104_cleartext",
        "sensitivity": sens,
        "summary": f"IEC 60870-5-104 APCI-style start (0x68){port_note} — telecontrol ASDUs may be visible in cleartext",
        "evidence_preview_hex": _hex_preview(pl),
        "dedupe_key": "104",
    }


def _try_s7_tpkt(pl: bytes, meta: PacketMetadata) -> Optional[dict[str, Any]]:
    if meta.dst_port != 102 and meta.src_port != 102:
        return None
    if len(pl) < 7 or pl[0] != 0x03 or pl[1] != 0x00:
        return None
    tpkt_len = int.from_bytes(pl[2:4], "big")
    if tpkt_len < 7 or tpkt_len > 2048:
        return None
    return {
        "category": "s7comm_cleartext",
        "sensitivity": "HIGH",
        "summary": "Siemens TPKT/COTP-style envelope in cleartext (S7comm path)",
        "evidence_preview_hex": _hex_preview(pl),
        "dedupe_key": "s7",
    }


def _try_dnp3(pl: bytes, meta: PacketMetadata) -> Optional[dict[str, Any]]:
    if meta.dst_port != 20000 and meta.src_port != 20000:
        return None
    if len(pl) < 10 or pl[0:2] != b"\x05\x64":
        return None
    return {
        "category": "dnp3_cleartext",
        "sensitivity": "HIGH",
        "summary": "DNP3 link header (0x05 0x64) in cleartext",
        "evidence_preview_hex": _hex_preview(pl),
        "dedupe_key": "dnp3",
    }


def _try_opcua_binary(pl: bytes, meta: PacketMetadata) -> Optional[dict[str, Any]]:
    if meta.dst_port != 4840 and meta.src_port != 4840:
        return None
    if pl[:3] == b"HEL" and len(pl) >= 8:
        return {
            "category": "opcua_cleartext",
            "sensitivity": "MEDIUM",
            "summary": "OPC UA binary HEL message in cleartext (handshake / framing)",
            "evidence_preview_hex": _hex_preview(pl),
            "dedupe_key": "opcua",
        }
    return None


def _try_enip_register(pl: bytes, meta: PacketMetadata) -> Optional[dict[str, Any]]:
    if meta.dst_port != 44818 and meta.src_port != 44818:
        return None
    if len(pl) < 4:
        return None
    cmd = int.from_bytes(pl[0:2], "little")
    if cmd != 0x0065:
        return None
    return {
        "category": "enip_cleartext",
        "sensitivity": "MEDIUM",
        "summary": "EtherNet/IP Register Session command in cleartext (CIP over TCP)",
        "evidence_preview_hex": _hex_preview(pl),
        "dedupe_key": "enip65",
    }


def _try_bacnet_udp(pl: bytes, meta: PacketMetadata) -> Optional[dict[str, Any]]:
    if meta.dst_port != 47808 and meta.src_port != 47808:
        return None
    if len(pl) < 4 or pl[0] != 0x81:
        return None
    return {
        "category": "bacnet_ip_cleartext",
        "sensitivity": "MEDIUM",
        "summary": "BACnet/IP BVLC (0x81) in cleartext UDP — object/property data may be exposed",
        "evidence_preview_hex": _hex_preview(pl),
        "dedupe_key": "bacnet",
    }


def _try_generic_ics_tcp(meta: PacketMetadata, pl: bytes) -> Optional[dict[str, Any]]:
    if len(pl) < 12:
        return None
    port = meta.dst_port if meta.dst_port in _ICS_TCP_PORTS else (
        meta.src_port if meta.src_port in _ICS_TCP_PORTS else None
    )
    if port is None:
        return None
    info = lookup_port(port)
    if not info or not info.is_ics:
        return None
    label = info.service_name
    return {
        "category": "ics_tcp_port_cleartext_payload",
        "sensitivity": "MEDIUM",
        "summary": f"Non-TLS TCP payload on ICS-associated port {port} ({label}) — application data may be readable",
        "evidence_preview_hex": _hex_preview(pl),
        "dedupe_key": f"gen{port}",
    }


def _try_http_ot(pl: bytes, meta: PacketMetadata) -> Optional[dict[str, Any]]:
    if not (
        pl.startswith(b"GET ")
        or pl.startswith(b"POST ")
        or pl.startswith(b"PUT ")
        or pl.startswith(b"HTTP/")
    ):
        return None
    head = pl[:4096]
    m = _HTTP_OT_NEEDLE.search(head)
    if not m:
        return None
    start = max(0, m.start() - 24)
    excerpt = head[start : m.end() + 48]
    try:
        asc = excerpt.decode("utf-8", errors="replace")
    except Exception:
        asc = excerpt.hex()
    asc = " ".join(asc.split())[:220]
    return {
        "category": "http_cleartext_ot_context",
        "sensitivity": "MEDIUM",
        "summary": "HTTP cleartext with OT/ICS-related token in headers or early body (URLs, APIs, vendor tokens)",
        "http_context_excerpt": asc,
        "evidence_preview_hex": _hex_preview(pl, 24),
        "dedupe_key": "httpot",
    }


def inspect_tcp_ot_cleartext(meta: PacketMetadata, pl: bytes) -> list[dict[str, Any]]:
    if not pl or len(pl) < 4:
        return []
    if _tls_client_hello_pl(pl):
        return []
    out: list[dict[str, Any]] = []
    for fn in (
        _try_modbus_tcp,
        _try_iec104,
        _try_s7_tpkt,
        _try_dnp3,
        _try_opcua_binary,
        _try_enip_register,
    ):
        hit = fn(pl, meta)
        if hit:
            out.append(hit)
            break
    if not any(x["category"] == "modbus_tcp_cleartext" for x in out):
        u = _try_modbus_port_unknown(pl, meta)
        if u:
            out.append(u)
    if not out:
        g = _try_generic_ics_tcp(meta, pl)
        if g:
            out.append(g)
    http_hit = _try_http_ot(pl, meta)
    if http_hit:
        out.append(http_hit)
    return out


def inspect_udp_ot_cleartext(meta: PacketMetadata, pl: bytes) -> list[dict[str, Any]]:
    if not pl:
        return []
    out: list[dict[str, Any]] = []
    b = _try_bacnet_udp(pl, meta)
    if b:
        out.append(b)
    if meta.dst_port == 161 or meta.src_port == 161:
        comm = _snmp_v1_v2c_community_redacted(pl)
        if comm:
            out.append(
                {
                    "category": "snmp_cleartext_community",
                    "sensitivity": "HIGH",
                    "summary": "SNMPv1/v2c-style message: community string position parsed (value redacted below)",
                    "snmp_community_redacted": comm,
                    "evidence_preview_hex": _hex_preview(pl),
                    "dedupe_key": "snmp",
                },
            )
    return out
