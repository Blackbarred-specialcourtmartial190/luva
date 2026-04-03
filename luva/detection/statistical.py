"""Statistical anomaly hints — bounded memory (Welford / aggregates, large-PCAP safe)."""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from typing import Optional

from luva.core.config import AnomalyCategory, Severity
from luva.models.event import AnomalyEvent
from luva.models.flow import NetworkFlow
from luva.parsers.base import ProtocolFrame

logger = logging.getLogger(__name__)

_MAX_KNOWN_PAIRS = 400_000


class _Welford:
    __slots__ = ("n", "mean", "m2")

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0

    def add(self, x: float) -> None:
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        d2 = x - self.mean
        self.m2 += d * d2

    def std(self) -> float:
        if self.n < 2:
            return 0.0
        return math.sqrt(max(self.m2 / (self.n - 1), 0.0))


class StatisticalDetector:
    """Lightweight statistical signals without storing every frame size."""

    def __init__(self, z_threshold: float = 3.0, iqr_multiplier: float = 1.5):
        self.z_threshold = z_threshold
        self.iqr_multiplier = iqr_multiplier

        self._known_pairs: set[tuple[str, str]] = set()
        self._fc_freq: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
        self._total_frames_per_proto: dict[str, int] = defaultdict(int)
        self._proto_sizes: defaultdict[str, _Welford] = defaultdict(_Welford)

        self._anomalies: list[AnomalyEvent] = []

    def learn_from_frame(self, frame: ProtocolFrame) -> None:
        pair = (frame.src_ip, frame.dst_ip)
        if len(self._known_pairs) < _MAX_KNOWN_PAIRS:
            self._known_pairs.add(pair)

        if frame.function_code is not None:
            self._fc_freq[frame.protocol][frame.function_code] += 1
            self._total_frames_per_proto[frame.protocol] += 1

        if frame.raw_bytes:
            self._proto_sizes[frame.protocol].add(float(len(frame.raw_bytes)))

    def analyze_flows(self, flows: list[NetworkFlow]) -> list[AnomalyEvent]:
        events: list[AnomalyEvent] = []
        for flow in flows:
            events.extend(self._check_timing_anomaly(flow))
            events.extend(self._check_size_anomaly(flow))
        self._anomalies.extend(events)
        return events

    def check_new_communication_pair(self, frame: ProtocolFrame) -> Optional[AnomalyEvent]:
        pair = (frame.src_ip, frame.dst_ip)
        reverse_pair = (frame.dst_ip, frame.src_ip)

        if len(self._known_pairs) >= _MAX_KNOWN_PAIRS:
            return None

        if len(self._known_pairs) > 20:
            if pair not in self._known_pairs and reverse_pair not in self._known_pairs:
                event = AnomalyEvent(
                    severity=Severity.INFO,
                    category=AnomalyCategory.NETWORK,
                    rule_id="STAT-001",
                    rule_name="New Communication Pair",
                    description=(
                        f"Previously unseen pair: {frame.src_ip} → {frame.dst_ip} ({frame.protocol})"
                    ),
                    timestamp=frame.timestamp,
                    evidence={
                        "src_ip": frame.src_ip,
                        "dst_ip": frame.dst_ip,
                        "protocol": frame.protocol,
                        "known_pairs_count": len(self._known_pairs),
                    },
                    affected_assets=[frame.src_ip, frame.dst_ip],
                    confidence=0.7,
                    tags=["new-pair", "network-change"],
                    packet_number=frame.packet_number,
                )
                self._known_pairs.add(pair)
                return event

        self._known_pairs.add(pair)
        return None

    def check_rare_function_code(self, frame: ProtocolFrame) -> Optional[AnomalyEvent]:
        if frame.function_code is None:
            return None

        proto = frame.protocol
        total = self._total_frames_per_proto.get(proto, 0)

        if total < 100:
            return None

        fc_count = self._fc_freq.get(proto, {}).get(frame.function_code, 0)
        frequency = fc_count / total if total > 0 else 0

        if frequency < 0.001 and fc_count < 3:
            severity = Severity.MEDIUM if frame.is_write_operation else Severity.LOW

            return AnomalyEvent(
                severity=severity,
                category=AnomalyCategory.BEHAVIOR,
                rule_id="STAT-002",
                rule_name="Rare Function Code Usage",
                description=(
                    f"Rare function code: {proto} FC=0x{frame.function_code:02X} "
                    f"({frame.function_name}) — freq {frequency:.4%} ({fc_count}/{total})"
                ),
                timestamp=frame.timestamp,
                evidence={
                    "src_ip": frame.src_ip,
                    "dst_ip": frame.dst_ip,
                    "protocol": proto,
                    "function_code": f"0x{frame.function_code:02X}",
                    "frequency": round(frequency, 6),
                    "count": fc_count,
                    "total": total,
                },
                affected_assets=[frame.src_ip],
                confidence=0.6,
                tags=["rare-function", "anomaly"],
                packet_number=frame.packet_number,
            )
        return None

    def _check_timing_anomaly(self, flow: NetworkFlow) -> list[AnomalyEvent]:
        """Flag highly irregular inter-arrival times (aggregate CV, no per-packet array)."""
        if flow.ipt_observation_count < 20:
            return []

        mean = flow.avg_inter_packet_time
        std = flow.inter_packet_time_std
        if mean <= 0 or std <= 0:
            return []

        cv = std / mean
        if cv > 2.5 and flow.packet_count > 40:
            return [
                AnomalyEvent(
                    severity=Severity.LOW,
                    category=AnomalyCategory.BEHAVIOR,
                    rule_id="STAT-003",
                    rule_name="Irregular Flow Timing",
                    description=(
                        f"High IPT variability: {flow.src_ip}:{flow.src_port} → "
                        f"{flow.dst_ip}:{flow.dst_port} — mean {mean:.3f}s, σ {std:.3f}s (CV {cv:.2f})"
                    ),
                    evidence={
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "protocol": flow.ics_protocol or flow.transport_protocol,
                        "mean_ipt": round(mean, 6),
                        "std_ipt": round(std, 6),
                        "coefficient_of_variation": round(cv, 4),
                    },
                    affected_assets=[flow.src_ip, flow.dst_ip],
                    confidence=0.6,
                    tags=["timing", "statistical"],
                )
            ]
        return []

    def _check_size_anomaly(self, flow: NetworkFlow) -> list[AnomalyEvent]:
        """Flag strong packet-size dispersion on a flow (aggregate only)."""
        n = flow.packet_count
        if n < 20:
            return []

        mean = flow.avg_packet_size
        std = flow.packet_length_std
        if mean <= 0 or std <= 0:
            return []

        cv = std / mean
        if cv > 0.85 and n > 30:
            return [
                AnomalyEvent(
                    severity=Severity.LOW,
                    category=AnomalyCategory.BEHAVIOR,
                    rule_id="STAT-004",
                    rule_name="Packet Size Dispersion",
                    description=(
                        f"High packet size spread: {flow.src_ip} → {flow.dst_ip} — "
                        f"mean {mean:.0f} B, σ {std:.0f} B (CV {cv:.2f})"
                    ),
                    evidence={
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "protocol": flow.ics_protocol or flow.transport_protocol,
                        "mean_size": round(mean, 1),
                        "std_size": round(std, 1),
                        "coefficient_of_variation": round(cv, 4),
                    },
                    affected_assets=[flow.src_ip, flow.dst_ip],
                    confidence=0.55,
                    tags=["packet-size", "statistical"],
                )
            ]
        return []

    def get_all_anomalies(self) -> list[AnomalyEvent]:
        return self._anomalies.copy()

    @property
    def stats(self) -> dict:
        return {
            "known_pairs": len(self._known_pairs),
            "protocols_tracked": len(self._fc_freq),
            "anomalies_detected": len(self._anomalies),
        }
