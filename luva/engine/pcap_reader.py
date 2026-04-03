"""PCAP/PCAPNG reader — Scapy-based streaming read and packet metadata extraction."""

from __future__ import annotations

import gzip
import logging
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional, Tuple

from scapy.all import PcapReader, PcapNgReader, Ether, IP, TCP, UDP, Raw, conf

from luva.core.exceptions import PCAPReadError, PCAPValidationError

logger = logging.getLogger(__name__)

# Quiet Scapy
conf.verb = 0


def _peek_looks_like_git_lfs_pointer(peek: bytes) -> bool:
    if not peek:
        return False
    if b"git-lfs.github.com" in peek:
        return True
    stripped = peek.lstrip()
    return bool(stripped.startswith(b"version ") and b"git-lfs" in peek.lower())


def file_looks_like_git_lfs_pointer(filepath: Path | str, *, max_read: int = 512) -> bool:
    """Return True if the path is a Git LFS text pointer, not a binary capture."""
    path = Path(filepath)
    try:
        with open(path, "rb") as f:
            peek = f.read(max_read)
    except OSError:
        return False
    return _peek_looks_like_git_lfs_pointer(peek)


@dataclass
class PacketMetadata:
    """Structured metadata extracted from one packet."""
    packet_number: int
    timestamp: datetime
    length: int

    # L2
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    eth_type: Optional[int] = None

    # L3
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_proto: Optional[int] = None
    ttl: Optional[int] = None

    # L4
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    transport: Optional[str] = None  # "TCP" or "UDP"
    tcp_flags: Optional[str] = None

    # L7
    payload: bytes = field(default_factory=bytes, repr=False)
    payload_length: int = 0

    pcap_file: Optional[str] = None


class PCAPReader:
    """Stream PCAP/PCAPNG (and .pcap.gz / .pcapng.gz) with minimal memory use."""

    SUPPORTED_EXTENSIONS = {".pcap", ".pcapng", ".gz"}
    PCAP_MAGIC_BYTES = {
        b"\xd4\xc3\xb2\xa1",  # libpcap microsecond (little-endian)
        b"\xa1\xb2\xc3\xd4",  # libpcap microsecond (big-endian)
        b"\x4d\x3c\xb2\xa1",  # libpcap nanosecond (little-endian)
        b"\xa1\xb2\x3c\x4d",  # libpcap nanosecond (big-endian)
        b"\x0a\x0d\x0d\x0a",  # pcapng
    }

    def __init__(self, filepath: Path | str):
        self.filepath = Path(filepath)
        self._temp_file: Optional[str] = None
        self._packet_count = 0
        self._validate()

    def _validate(self) -> None:
        """Existence, extension, LFS pointer, and magic-byte checks."""
        if not self.filepath.exists():
            raise PCAPValidationError(
                f"File not found: {self.filepath}",
                {"filepath": str(self.filepath)},
            )

        if not self.filepath.is_file():
            raise PCAPValidationError(
                f"Not a regular file: {self.filepath}",
                {"filepath": str(self.filepath)},
            )

        suffix = self.filepath.suffix.lower()
        if suffix == ".gz":
            # Require .pcap.gz / .pcapng.gz naming
            stem_suffix = Path(self.filepath.stem).suffix.lower()
            if stem_suffix not in (".pcap", ".pcapng"):
                raise PCAPValidationError(
                    f"Unsupported compressed capture name (expected .pcap.gz / .pcapng.gz): {self.filepath.name}",
                    {"filepath": str(self.filepath)},
                )
        elif suffix not in self.SUPPORTED_EXTENSIONS:
            raise PCAPValidationError(
                f"Unsupported file extension: {suffix}",
                {"filepath": str(self.filepath), "extension": suffix},
            )

        # Magic bytes / placeholder checks
        actual_path = self._get_actual_path()
        try:
            with open(actual_path, "rb") as f:
                peek = f.read(256)
                if _peek_looks_like_git_lfs_pointer(peek):
                    raise PCAPValidationError(
                        "Git LFS pointer file (not a binary capture). Run `git lfs pull` to fetch objects.",
                        {"filepath": str(self.filepath), "kind": "git_lfs_pointer"},
                    )
                magic = peek[:4]
                if magic not in self.PCAP_MAGIC_BYTES:
                    raise PCAPValidationError(
                        f"Invalid capture file (unrecognized magic bytes {magic.hex()}): {self.filepath.name}",
                        {"magic_bytes": magic.hex(), "filepath": str(self.filepath)},
                    )
        except OSError as e:
            raise PCAPReadError(f"Cannot read file: {e}", {"filepath": str(self.filepath)})
        finally:
            pass

    def _get_actual_path(self) -> Path:
        """Decompress .gz to a temp file when needed."""
        if self.filepath.suffix.lower() == ".gz":
            if self._temp_file is None:
                tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
                self._temp_file = tmp.name
                try:
                    with gzip.open(self.filepath, "rb") as gz_in:
                        with open(tmp.name, "wb") as f_out:
                            shutil.copyfileobj(gz_in, f_out)
                    logger.info("Decompressed capture %s to %s", self.filepath.name, tmp.name)
                except Exception as e:
                    raise PCAPReadError(
                        f"Failed to decompress capture: {e}",
                        {"filepath": str(self.filepath)},
                    )
            return Path(self._temp_file)
        return self.filepath

    def _extract_packet_metadata(self, packet, packet_num: int) -> PacketMetadata:
        """Map Scapy packet to PacketMetadata."""
        # Timestamp
        try:
            ts = float(packet.time)
            timestamp = datetime.fromtimestamp(ts, tz=timezone.utc)
        except (AttributeError, ValueError, OSError):
            timestamp = datetime.now(tz=timezone.utc)

        meta = PacketMetadata(
            packet_number=packet_num,
            timestamp=timestamp,
            length=len(packet),
            pcap_file=self.filepath.name,
        )

        # L2 Ethernet
        if packet.haslayer(Ether):
            eth = packet[Ether]
            meta.src_mac = eth.src
            meta.dst_mac = eth.dst
            meta.eth_type = eth.type

        # L3 IP
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            meta.src_ip = ip_layer.src
            meta.dst_ip = ip_layer.dst
            meta.ip_proto = ip_layer.proto
            meta.ttl = ip_layer.ttl

        # L4 TCP
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            meta.src_port = tcp_layer.sport
            meta.dst_port = tcp_layer.dport
            meta.transport = "TCP"
            meta.tcp_flags = str(tcp_layer.flags)

        # L4 UDP
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            meta.src_port = udp_layer.sport
            meta.dst_port = udp_layer.dport
            meta.transport = "UDP"

        # L7 payload
        if packet.haslayer(Raw):
            raw = packet[Raw].load
            meta.payload = raw
            meta.payload_length = len(raw)

        return meta

    def read_packets(self, chunk_size: int = 0) -> Generator[PacketMetadata, None, None]:
        """Yield PacketMetadata for each packet (optionally stop after chunk_size).

        Args:
            chunk_size: 0 = read all; >0 = max packets to yield.

        Yields:
            PacketMetadata instances.
        """
        actual_path = self._get_actual_path()
        packet_num = 0
        yielded = 0

        try:
            # PCAP vs PCAPNG reader
            reader_cls = PcapReader
            if actual_path.suffix.lower() == ".pcapng" or self.filepath.suffix.lower() == ".pcapng":
                reader_cls = PcapNgReader

            # Refine reader from magic
            with open(actual_path, "rb") as f:
                magic = f.read(4)
                if magic == b"\x0a\x0d\x0d\x0a":
                    reader_cls = PcapNgReader

            with reader_cls(str(actual_path)) as reader:
                for packet in reader:
                    packet_num += 1
                    try:
                        meta = self._extract_packet_metadata(packet, packet_num)
                        yield meta
                        yielded += 1

                        if chunk_size > 0 and yielded >= chunk_size:
                            break

                    except Exception as e:
                        logger.warning("Packet #%s could not be parsed: %s", packet_num, e)
                        continue

        except Exception as e:
            raise PCAPReadError(
                f"PCAP read error: {e}",
                {"filepath": str(self.filepath), "packets_read": packet_num}
            )

        self._packet_count = packet_num
        logger.info("Read %s packets from %s", packet_num, self.filepath.name)

    def iter_scapy_packets(self, chunk_size: int = 0) -> Generator[Tuple[int, Any], None, None]:
        """Yield ``(1-based packet number, scapy packet)`` for PCAP export (same path/gzip rules as :meth:`read_packets`)."""
        actual_path = self._get_actual_path()
        packet_num = 0
        yielded = 0

        try:
            reader_cls = PcapReader
            if actual_path.suffix.lower() == ".pcapng" or self.filepath.suffix.lower() == ".pcapng":
                reader_cls = PcapNgReader

            with open(actual_path, "rb") as f:
                magic = f.read(4)
                if magic == b"\x0a\x0d\x0d\x0a":
                    reader_cls = PcapNgReader

            with reader_cls(str(actual_path)) as reader:
                for packet in reader:
                    packet_num += 1
                    try:
                        yield packet_num, packet
                        yielded += 1
                        if chunk_size > 0 and yielded >= chunk_size:
                            break
                    except Exception as e:
                        logger.warning("Packet #%s raw iter failed: %s", packet_num, e)
                        continue

        except Exception as e:
            raise PCAPReadError(
                f"PCAP read error: {e}",
                {"filepath": str(self.filepath), "packets_read": packet_num},
            )

    def get_file_info(self) -> dict:
        """Basic file stats for reporting."""
        stat = self.filepath.stat()
        return {
            "filepath": str(self.filepath),
            "filename": self.filepath.name,
            "size_bytes": stat.st_size,
            "size_mb": round(stat.st_size / (1024 * 1024), 2),
            "format": self.filepath.suffix.lower(),
            "compressed": self.filepath.suffix.lower() == ".gz",
        }

    def __del__(self):
        """Remove temp decompressed file if any."""
        if self._temp_file:
            try:
                Path(self._temp_file).unlink(missing_ok=True)
            except OSError:
                pass
