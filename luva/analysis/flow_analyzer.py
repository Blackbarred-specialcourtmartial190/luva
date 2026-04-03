"""Flow analyzer — tracks 5-tuple flows, periodicity, and aggregate statistics."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Optional

from luva.engine.pcap_reader import PacketMetadata
from luva.models.flow import NetworkFlow
from luva.parsers.base import ProtocolFrame

logger = logging.getLogger(__name__)


class FlowAnalyzer:
    """5-tuple flow engine: each (src_ip, dst_ip, src_port, dst_port, transport) is one flow."""

    def __init__(self):
        self._flows: dict[str, NetworkFlow] = {}  # flow_key → NetworkFlow
        self._last_packet_time: dict[str, float] = {}  # flow_key → last packet time (epoch seconds)

    @staticmethod
    def _make_flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, transport: str) -> str:
        """Build canonical flow key string."""
        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{transport}"

    def process_packet(self, packet: PacketMetadata) -> Optional[str]:
        """Attach packet to its flow table entry.

        Returns:
            Flow key, or None if L4 metadata is missing.
        """
        sip, dip = packet.src_ip, packet.dst_ip
        sp, dp, tr = packet.src_port, packet.dst_port, packet.transport
        if sip is None or dip is None or sp is None or dp is None or tr is None:
            return None

        flow_key = self._make_flow_key(sip, dip, sp, dp, tr)

        if flow_key not in self._flows:
            self._flows[flow_key] = NetworkFlow(
                src_ip=sip,
                dst_ip=dip,
                src_port=sp,
                dst_port=dp,
                transport_protocol=tr,
            )

        flow = self._flows[flow_key]

        # Inter-packet timing
        ts = packet.timestamp.timestamp()
        if flow_key in self._last_packet_time:
            ipt = ts - self._last_packet_time[flow_key]
            if 0 < ipt < 3600:
                flow.record_inter_packet_time(ipt)
        self._last_packet_time[flow_key] = ts

        flow.packet_count += 1
        flow.byte_count += packet.length
        flow.record_packet_length(packet.length)

        if flow.start_time is None or packet.timestamp < flow.start_time:
            flow.start_time = packet.timestamp
        if flow.end_time is None or packet.timestamp > flow.end_time:
            flow.end_time = packet.timestamp

        return flow_key

    def process_frame(self, frame: ProtocolFrame, flow_key: str) -> None:
        """Merge parsed ICS frame metadata into the flow."""
        if flow_key not in self._flows:
            return

        flow = self._flows[flow_key]
        flow.ics_protocols_seen.add(frame.protocol)
        if len(flow.ics_protocols_seen) > 1:
            flow.ics_protocol = ", ".join(sorted(flow.ics_protocols_seen))
        else:
            flow.ics_protocol = next(iter(flow.ics_protocols_seen))

        if frame.function_code is not None:
            flow.function_codes_seen.add(frame.function_code)

        if frame.protocol == "Modbus" and frame.function_code is not None and frame.is_write_operation:
            flow.modbus_write_fcs_seen.add(frame.function_code)
        if frame.protocol == "S7" and frame.function_code is not None:
            flow.s7_service_codes_seen.add(frame.function_code)

        if frame.is_write_operation:
            flow.has_write_operations = True

        if frame.is_exception:
            flow.exception_count += 1

    def get_flow(self, flow_key: str) -> Optional[NetworkFlow]:
        """Return one flow by key."""
        return self._flows.get(flow_key)

    def get_all_flows(self) -> list[NetworkFlow]:
        """Return all flows."""
        return list(self._flows.values())

    def get_top_talkers(self, n: int = 10) -> list[tuple[str, int]]:
        """Top source IPs by packet count."""
        ip_counts: dict[str, int] = defaultdict(int)
        for flow in self._flows.values():
            ip_counts[flow.src_ip] += flow.packet_count

        return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_top_flows(self, n: int = 10) -> list[NetworkFlow]:
        """Largest flows by packet count."""
        return sorted(self._flows.values(), key=lambda f: f.packet_count, reverse=True)[:n]

    def get_protocol_distribution(self) -> dict[str, int]:
        """Packet counts per ICS or transport label (multi-protocol flows count toward each seen ICS)."""
        dist: dict[str, int] = defaultdict(int)
        for flow in self._flows.values():
            if flow.ics_protocols_seen:
                for proto in flow.ics_protocols_seen:
                    dist[proto] += flow.packet_count
            else:
                proto = flow.ics_protocol or flow.transport_protocol
                dist[proto] += flow.packet_count
        return dict(sorted(dist.items(), key=lambda x: x[1], reverse=True))

    def get_communication_matrix(self) -> dict[str, dict[str, int]]:
        """Adjacency-style counts: src_ip → dst_ip → packet_count."""
        matrix: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for flow in self._flows.values():
            matrix[flow.src_ip][flow.dst_ip] += flow.packet_count
        return {k: dict(v) for k, v in matrix.items()}

    def detect_periodic_flows(self, min_packets: int = 10, cv_threshold: float = 0.3) -> list[dict]:
        """Detect low-jitter (polling-like) flows using streaming IPT mean/std (memory-safe)."""
        import math

        periodic = []
        for key, flow in self._flows.items():
            if flow.packet_count < min_packets or flow.ipt_observation_count < min_packets - 1:
                continue

            mean_ipt = flow.avg_inter_packet_time
            std_ipt = flow.inter_packet_time_std

            if mean_ipt > 0 and not math.isnan(std_ipt):
                cv = std_ipt / mean_ipt
                if cv < cv_threshold:
                    mode_name = "polling" if flow.ics_protocol else "communication"
                    periodic.append(
                        {
                            "flow_key": key,
                            "src_ip": flow.src_ip,
                            "dst_ip": flow.dst_ip,
                            "protocol": flow.ics_protocol or flow.transport_protocol,
                            "period_seconds": round(mean_ipt, 4),
                            "cv": round(cv, 4),
                            "packet_count": flow.packet_count,
                            "description": f"~{mean_ipt:.2f}s periodic {mode_name}",
                        }
                    )

        return sorted(periodic, key=lambda x: x["cv"])

    def get_temporal_heatmap(self, bucket_seconds: int = 3600) -> dict[str, int]:
        """Bucket packet counts by coarse time window (UTC labels)."""
        from datetime import datetime, timezone

        heatmap: dict[str, int] = defaultdict(int)

        for flow in self._flows.values():
            if flow.start_time:
                ts = flow.start_time.timestamp()
                bucket = int(ts // bucket_seconds) * bucket_seconds
                bucket_dt = datetime.fromtimestamp(bucket, tz=timezone.utc)
                key = bucket_dt.strftime("%Y-%m-%d %H:%M")
                heatmap[key] += flow.packet_count

        return dict(sorted(heatmap.items()))

    @property
    def flow_count(self) -> int:
        return len(self._flows)

    @property
    def stats(self) -> dict:
        """Aggregate flow statistics."""
        total_packets = sum(f.packet_count for f in self._flows.values())
        total_bytes = sum(f.byte_count for f in self._flows.values())
        ics_flows = sum(1 for f in self._flows.values() if f.ics_protocol or f.ics_protocols_seen)
        write_flows = sum(1 for f in self._flows.values() if f.has_write_operations)

        return {
            "total_flows": self.flow_count,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "ics_flows": ics_flows,
            "write_operation_flows": write_flows,
            "flows_with_exceptions": sum(1 for f in self._flows.values() if f.exception_count > 0),
        }
