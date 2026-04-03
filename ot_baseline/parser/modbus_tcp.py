"""
Best-effort Modbus/TCP function-code extraction from captured segments.

Without TCP reassembly, multi-segment ADUs may be missed; the sliding window
recovers many single-segment exchanges seen in OT captures.
"""

from __future__ import annotations

import struct
from typing import Iterator

# Practical SOC grouping (not exhaustive Modbus encap / user FCs)
MODBUS_READ_FCS = frozenset({1, 2, 3, 4})
MODBUS_WRITE_FCS = frozenset({5, 6, 15, 16, 22, 24})


def iter_modbus_requests_from_tcp_payload(payload: bytes) -> Iterator[tuple[int, str]]:
    """
    Yield (function_code, category) for each plausible request PDU in ``payload``.

    MBAP: TID(2) PID(2)=0 LEN(2) then LEN bytes = Unit(1)+PDU. FC is first PDU byte.
    """
    if len(payload) < 8:
        return
    i = 0
    end = len(payload)
    while i + 8 <= end:
        try:
            _tid, proto_id, length = struct.unpack_from(">HHH", payload, i)
        except struct.error:
            break
        # LEN = unit (1) + PDU; need at least FC
        if proto_id != 0 or length < 2 or length > 260:
            i += 1
            continue
        frame_end = i + 6 + length
        if frame_end > end:
            i += 1
            continue
        fc_byte = payload[i + 7]
        fc = fc_byte & 0x7F
        if fc_byte & 0x80:
            cat = "other"
        elif fc in MODBUS_READ_FCS:
            cat = "read"
        elif fc in MODBUS_WRITE_FCS:
            cat = "write"
        else:
            cat = "other"
        yield (fc, cat)
        i = frame_end


def extract_first_modbus_fc(payload: bytes) -> tuple[int | None, str | None]:
    """Return first (function_code, category) or (None, None)."""
    for fc, cat in iter_modbus_requests_from_tcp_payload(payload):
        return fc, cat
    return None, None
