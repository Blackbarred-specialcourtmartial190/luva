"""Chain-of-custody style evidence for audit reports (file integrity hashes)."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def sha256_file(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> str:
    """Streaming SHA-256 of file bytes (as stored on disk — e.g. ``.pcap.gz`` is hashed compressed)."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            block = f.read(chunk_size)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def compute_input_evidence(paths: list[Path]) -> list[dict[str, Any]]:
    """Per-input metadata for auditors: path, size, SHA-256."""
    out: list[dict[str, Any]] = []
    for p in paths:
        if not p.is_file():
            continue
        try:
            st = p.stat()
            out.append(
                {
                    "path": str(p.resolve()),
                    "filename": p.name,
                    "size_bytes": st.st_size,
                    "sha256": sha256_file(p),
                },
            )
        except OSError:
            continue
    return out
