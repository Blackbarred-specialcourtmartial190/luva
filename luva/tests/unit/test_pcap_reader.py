"""PCAPReader validation and Git LFS pointer detection."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("scapy")
from scapy.all import IP, Raw, TCP, wrpcap  # noqa: E402

from luva.core.exceptions import PCAPValidationError
from luva.engine.pcap_reader import PCAPReader, file_looks_like_git_lfs_pointer


def test_reader_rejects_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "nope.pcap"
    with pytest.raises(PCAPValidationError, match="not found"):
        PCAPReader(missing)


def test_reader_rejects_bad_extension(tmp_path: Path) -> None:
    p = tmp_path / "x.txt"
    p.write_text("not a pcap", encoding="utf-8")
    with pytest.raises(PCAPValidationError, match="Unsupported file extension"):
        PCAPReader(p)


def test_reader_rejects_git_lfs_pointer(tmp_path: Path) -> None:
    p = tmp_path / "fake.pcap"
    p.write_text(
        "version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 123\n",
        encoding="utf-8",
    )
    with pytest.raises(PCAPValidationError, match="Git LFS"):
        PCAPReader(p)


def test_file_looks_like_git_lfs_pointer(tmp_path: Path) -> None:
    p = tmp_path / "ptr.pcap"
    p.write_bytes(b"version https://git-lfs.github.com/spec/v1\n")
    assert file_looks_like_git_lfs_pointer(p) is True


def test_reader_reads_minimal_pcap(tmp_path: Path) -> None:
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=502) / Raw(load=b"\x00" * 20)
    pcap = tmp_path / "one.pcap"
    wrpcap(str(pcap), [pkt])
    reader = PCAPReader(pcap)
    metas = list(reader.read_packets())
    assert len(metas) == 1
    assert metas[0].dst_port == 502
