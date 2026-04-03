"""Trim large src→dst matrices for bounded report size."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def trim_communication_matrix(
    matrix: dict[str, dict[str, int]],
    max_endpoints: int,
) -> tuple[dict[str, dict[str, int]], dict[str, Any]]:
    """Keep only the top-N busiest IPs (by total matrix traffic) and their mutual edges."""
    if not matrix:
        return matrix, {}
    if max_endpoints <= 0:
        return matrix, {}
    volume: dict[str, int] = defaultdict(int)
    for s, row in matrix.items():
        for d, c in row.items():
            volume[s] += c
            volume[d] += c
    if len(volume) <= max_endpoints:
        return matrix, {}
    ranked = sorted(volume.keys(), key=lambda ip: volume[ip], reverse=True)[:max_endpoints]
    keep = set(ranked)
    out: dict[str, dict[str, int]] = {}
    for s in keep:
        if s not in matrix:
            continue
        part = {d: c for d, c in matrix[s].items() if d in keep}
        if part:
            out[s] = part
    note = {
        "communication_matrix_truncated": True,
        "matrix_endpoint_cap": max_endpoints,
        "unique_ips_in_full_matrix": len(volume),
    }
    return out, note
