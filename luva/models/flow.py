"""Flow model — 5-tuple network flow with O(1) streaming statistics (large-PCAP safe)."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class NetworkFlow:
    """5-tuple flow. Packet lengths and inter-packet times use Welford's algorithm (bounded memory)."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport_protocol: str

    ics_protocol: Optional[str] = None
    #: All ICS application labels seen on this flow (multiple parsers may match).
    ics_protocols_seen: set[str] = field(default_factory=set)

    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    packet_count: int = 0
    byte_count: int = 0

    _len_n: int = field(default=0, repr=False)
    _len_mean: float = field(default=0.0, repr=False)
    _len_m2: float = field(default=0.0, repr=False)

    _ipt_n: int = field(default=0, repr=False)
    _ipt_mean: float = field(default=0.0, repr=False)
    _ipt_m2: float = field(default=0.0, repr=False)

    function_codes_seen: set[int] = field(default_factory=set)
    #: Modbus write-family function codes observed on this flow (5,6,15,16,…).
    modbus_write_fcs_seen: set[int] = field(default_factory=set)
    #: S7comm service / function codes (param[0]) seen on this flow.
    s7_service_codes_seen: set[int] = field(default_factory=set)
    has_write_operations: bool = False
    exception_count: int = 0

    def record_packet_length(self, length: int) -> None:
        """Incorporate one packet length (streaming mean/variance)."""
        self._len_n += 1
        delta = length - self._len_mean
        self._len_mean += delta / self._len_n
        delta2 = length - self._len_mean
        self._len_m2 += delta * delta2

    def record_inter_packet_time(self, ipt: float) -> None:
        """Incorporate one inter-arrival time in seconds (typically 0 < ipt < 3600)."""
        if ipt <= 0 or ipt >= 3600:
            return
        self._ipt_n += 1
        delta = ipt - self._ipt_mean
        self._ipt_mean += delta / self._ipt_n
        delta2 = ipt - self._ipt_mean
        self._ipt_m2 += delta * delta2

    @property
    def flow_id(self) -> str:
        key = f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.transport_protocol}"
        return hashlib.md5(key.encode()).hexdigest()[:12]

    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def packets_per_second(self) -> float:
        d = self.duration
        return self.packet_count / d if d > 0 else 0.0

    @property
    def bytes_per_second(self) -> float:
        d = self.duration
        return self.byte_count / d if d > 0 else 0.0

    @property
    def avg_packet_size(self) -> float:
        return self._len_mean if self._len_n else 0.0

    @property
    def packet_length_std(self) -> float:
        if self._len_n < 2:
            return 0.0
        return math.sqrt(max(self._len_m2 / (self._len_n - 1), 0.0))

    @property
    def avg_inter_packet_time(self) -> float:
        return self._ipt_mean if self._ipt_n else 0.0

    @property
    def inter_packet_time_std(self) -> float:
        if self._ipt_n < 2:
            return 0.0
        return math.sqrt(max(self._ipt_m2 / (self._ipt_n - 1), 0.0))

    @property
    def jitter(self) -> float:
        return self.inter_packet_time_std

    @property
    def ipt_observation_count(self) -> int:
        return self._ipt_n

    def to_dict(self) -> dict:
        protos = sorted(self.ics_protocols_seen) if self.ics_protocols_seen else (
            [self.ics_protocol] if self.ics_protocol else []
        )
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "transport_protocol": self.transport_protocol,
            "ics_protocol": self.ics_protocol,
            "ics_protocols": protos,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": round(self.duration, 3),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "packets_per_second": round(self.packets_per_second, 2),
            "bytes_per_second": round(self.bytes_per_second, 2),
            "avg_packet_size": round(self.avg_packet_size, 1),
            "packet_length_std": round(self.packet_length_std, 2),
            "avg_inter_packet_time": round(self.avg_inter_packet_time, 6),
            "jitter": round(self.jitter, 6),
            "function_codes_seen": sorted(self.function_codes_seen),
            "modbus_write_fcs_seen": sorted(self.modbus_write_fcs_seen),
            "s7_service_codes_seen": sorted(self.s7_service_codes_seen),
            "has_write_operations": self.has_write_operations,
            "exception_count": self.exception_count,
        }
