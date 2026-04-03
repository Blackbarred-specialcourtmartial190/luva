"""Tests for chain-of-custody input hashing."""

from __future__ import annotations

from pathlib import Path

from luva.analysis.evidence import compute_input_evidence, sha256_file


def test_sha256_file_matches_known_digest(tmp_path: Path) -> None:
    p = tmp_path / "blob.bin"
    p.write_bytes(b"abc")
    assert sha256_file(p) == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_compute_input_evidence_skips_missing(tmp_path: Path) -> None:
    p = tmp_path / "ok.bin"
    p.write_bytes(b"x")
    rows = compute_input_evidence([p, tmp_path / "nope"])
    assert len(rows) == 1
    assert rows[0]["filename"] == "ok.bin"
    assert rows[0]["size_bytes"] == 1
    assert len(rows[0]["sha256"]) == 64
