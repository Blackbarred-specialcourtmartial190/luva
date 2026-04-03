from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Optional

from luva.analysis.asset_tracker import AssetTracker
from luva.analysis.audit_workbook import build_audit_workbook
from luva.analysis.threat_patterns import build_threat_pattern_report
from luva.analysis.eks_report import build_eks_section, infer_eks_tags
from luva.analysis.ot_assets import build_ot_assets_export
from luva.analysis.deep_survey import DeepPacketSurvey
from luva.analysis.evidence import compute_input_evidence
from luva.analysis.flow_analyzer import FlowAnalyzer
from luva.analysis.pentest_insights import build_pentest_insights
from luva.analysis.communication_graph import build_communication_graph
from luva.analysis.topology import TopologyBuilder
from luva.core.config import AnalysisConfig, AnalysisMode
from luva.core.exceptions import PCAPReadError, PCAPValidationError
from luva.core.safety import PassivityGuard
from luva.detection.anomaly_engine import AnomalyEngine
from luva.engine.pcap_reader import PCAPReader, PacketMetadata
from luva.models.asset import Asset
from luva.models.event import AnomalyEvent
from luva.models.flow import NetworkFlow
from luva.models.topology import NetworkTopology
from luva import __version__
from luva.parsers import ALL_PARSER_CLASSES
from luva.parsers.base import BaseParser
from luva.utils.communication_matrix import trim_communication_matrix

logger = logging.getLogger(__name__)


def _build_event_timeline(anomalies: list[AnomalyEvent]) -> list[dict]:
    """Chronological anomaly rows for reports and SIEM-adjacent tooling."""
    rows: list[dict] = []
    for e in anomalies:
        rows.append(
            {
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "severity": e.severity.value,
                "rule_id": e.rule_id,
                "rule_name": e.rule_name,
                "description": e.description[:2000] if len(e.description) <= 2000 else e.description[:2000] + "…",
                "packet_number": e.packet_number,
                "pcap_file": e.pcap_file,
            }
        )
    rows.sort(key=lambda r: (r["timestamp"] or "", r["rule_id"]))
    return rows


@dataclass
class AnalysisResult:
    metadata: dict
    assets: list[Asset]
    flows: list[NetworkFlow]
    topology: NetworkTopology
    anomalies: list[AnomalyEvent]
    statistics: dict

    def to_dict(self, export_config: Optional[AnalysisConfig] = None) -> dict:
        """Serialize for reports. Optionally cap exported flows (see AnalysisConfig.max_flows_export)."""
        max_f: int | None = 1_000_000
        if export_config is not None:
            if export_config.max_flows_export == 0:
                max_f = None
            else:
                max_f = export_config.max_flows_export

        all_flows = self.flows
        total_flows = len(all_flows)
        if max_f is None or total_flows <= max_f:
            flows_export = all_flows
            omitted = 0
        else:
            flows_export = sorted(all_flows, key=lambda f: f.packet_count, reverse=True)[:max_f]
            omitted = total_flows - max_f

        protocols_seen = sorted({f.ics_protocol for f in all_flows if f.ics_protocol})

        meta = dict(self.metadata)
        if omitted > 0:
            meta["export_note"] = (
                f"Flows in this file are capped at {max_f} (highest packet counts). "
                f"Omitted {omitted} lower-volume flows; statistics used the full set."
            )

        assets_payload = [{**a.to_dict(), "eks_components": infer_eks_tags(a)} for a in self.assets]
        ot_assets_payload = build_ot_assets_export(self.assets)

        return {
            "metadata": meta,
            "summary": {
                "assets_discovered": len(self.assets),
                "ot_assets_discovered": len(ot_assets_payload),
                "flows_analyzed": total_flows,
                "flows_exported": len(flows_export),
                "flows_omitted_from_export": omitted,
                "anomalies_detected": len(self.anomalies),
                "critical_anomalies": sum(1 for e in self.anomalies if e.severity.value == "CRITICAL"),
                "protocols_seen": protocols_seen,
            },
            "assets": assets_payload,
            "ot_assets": ot_assets_payload,
            "flows": [f.to_dict() for f in flows_export],
            "topology": self.topology.to_dict(),
            "anomalies": [e.to_dict() for e in self.anomalies],
            "statistics": self.statistics,
            "eks": build_eks_section(self.assets),
        }


class AnalysisPipeline:
    def __init__(self, config: AnalysisConfig):
        self.config = config
        self.asset_tracker = AssetTracker()
        self.flow_analyzer = FlowAnalyzer()
        self.anomaly_engine = AnomalyEngine(min_severity=config.min_severity)
        self.parsers = self._load_parsers()

    def _parser_indices_for_packet(self, packet: PacketMetadata) -> list[int]:
        """Narrow parsers by L4 port; use payload-heuristic parsers only when no port matches."""
        ports = {packet.src_port, packet.dst_port}
        ports.discard(None)

        by_port: list[int] = []
        heuristic: list[int] = []
        for i, parser in enumerate(self.parsers):
            cls = type(parser)
            default_ports = getattr(cls, "DEFAULT_PORTS", None) or []
            if any(p in ports for p in default_ports):
                by_port.append(i)
            elif getattr(cls, "PAYLOAD_HEURISTIC", False):
                heuristic.append(i)

        if by_port:
            return by_port
        if heuristic:
            return heuristic
        return list(range(len(self.parsers)))

    def _load_parsers(self) -> list[BaseParser]:
        """Instantiate parsers enabled in config (protocol slugs, lowercase)."""
        allowed = {p.lower().strip() for p in self.config.protocols if p.strip()}
        if not allowed:
            return [cls() for cls in ALL_PARSER_CLASSES]
        parsers: list[BaseParser] = []
        for parser_cls in ALL_PARSER_CLASSES:
            slug = getattr(parser_cls, "PROTOCOL_SLUG", "") or ""
            if not slug:
                slug = getattr(parser_cls, "PROTOCOL_NAME", "").lower().replace(" ", "").replace("/", "")
            slug = slug.lower()
            if slug in allowed:
                parsers.append(parser_cls())
        return parsers

    def _user_status(self, message: str) -> None:
        """Short stdout line for CLI users (packet counter stays on stderr)."""
        if self.config.quiet:
            return
        print(f"[Luva] {message}", flush=True)

    def run(self) -> AnalysisResult:
        started = perf_counter()
        started_at = datetime.now(timezone.utc)

        PassivityGuard.validate_capture_inputs(self.config.input_files)

        skip_anomaly = self.config.mode in (AnalysisMode.ASSET_ONLY, AnalysisMode.TOPOLOGY_ONLY)
        skip_topology = self.config.mode == AnalysisMode.ANOMALY_ONLY

        self._user_status(
            f"Mode: {self.config.mode.value} · parsers: {len(self.parsers)} · "
            f"input file(s): {len(self.config.input_files)}",
        )

        default_rules = Path(__file__).resolve().parent.parent / "detection" / "rules"
        if not skip_anomaly:
            self._user_status("Loading YAML detection rules…")
            if default_rules.exists():
                n = self.anomaly_engine.load_rules(default_rules)
                self._user_status(f"Loaded {n} built-in YAML rule(s).")
            if self.config.custom_rules_dir:
                n2 = self.anomaly_engine.load_rules(self.config.custom_rules_dir)
                self._user_status(f"Loaded {n2} custom YAML rule(s).")
        else:
            self._user_status("Skipping anomaly rules (asset-only or topology-only mode).")

        total_packets = 0
        read_errors: list[dict[str, str]] = []
        deep_survey = DeepPacketSurvey()
        self._user_status("Reading packets, deep survey, asset/flow tracking, and protocol parsers…")
        for input_file in self.config.input_files:
            try:
                reader = PCAPReader(input_file)
            except (PCAPValidationError, PCAPReadError) as exc:
                logger.warning("Skipping unreadable capture %s: %s", input_file, exc)
                read_errors.append({"path": str(input_file), "detail": str(exc)})
                continue

            chunk = self.config.chunk_size if self.config.chunk_size > 0 else 0
            try:
                for packet in reader.read_packets(chunk_size=chunk):
                    total_packets += 1
                    pi = self.config.progress_packet_interval
                    if (
                        self.config.show_progress
                        and pi > 0
                        and total_packets % pi == 0
                    ):
                        sys.stderr.write(f"\rLuva: processed {total_packets:,} packets…")
                        sys.stderr.flush()
                    deep_survey.process(packet)
                    self.asset_tracker.process_packet(packet)
                    flow_key = self.flow_analyzer.process_packet(packet)

                    # Run every parser that matches — one capture may carry multiple ICS stacks
                    # or overlapping heuristics; do not stop at the first hit.
                    for idx in self._parser_indices_for_packet(packet):
                        parser = self.parsers[idx]
                        if not parser.can_parse(packet):
                            continue
                        frame = parser.parse(packet)
                        if frame is None:
                            continue

                        self.asset_tracker.process_frame(frame)
                        if flow_key:
                            self.flow_analyzer.process_frame(frame, flow_key)
                        if not skip_anomaly:
                            self.anomaly_engine.process_frame(frame)
            except PCAPReadError as exc:
                logger.warning("PCAP read failed for %s: %s", input_file, exc)
                read_errors.append({"path": str(input_file), "detail": str(exc)})
                continue

        if self.config.show_progress and total_packets > 0:
            sys.stderr.write("\n")
            sys.stderr.flush()

        self._user_status(f"Packet pass complete ({total_packets:,} IPv4/L2 frames processed). Inferring roles and risk…")
        self.asset_tracker.infer_roles()
        self.asset_tracker.calculate_risk_scores()

        flows = self.flow_analyzer.get_all_flows()
        if not skip_anomaly:
            self._user_status("Running flow-level and statistical anomaly checks…")
            self.anomaly_engine.analyze_flows(flows)
        anomalies = self.anomaly_engine.get_all_events() if not skip_anomaly else []

        assets_list = self.asset_tracker.get_all_assets()
        self._user_status(
            f"Building insights ({len(flows)} flows, {len(assets_list)} assets, {len(anomalies)} anomaly event(s))…",
        )
        deep_dict = deep_survey.to_dict()
        pentest = build_pentest_insights(flows, assets_list, anomalies, deep_dict)
        threat = build_threat_pattern_report(flows, assets_list, deep_dict)
        for item in reversed(threat.get("executive_findings", [])):
            pentest["passive_findings"].insert(0, item)
        pentest["summary_counts"] = {**pentest["summary_counts"], **threat.get("summary_counts", {})}
        audit_wb = build_audit_workbook(
            flows,
            assets_list,
            anomalies,
            deep_dict,
            pentest,
            threat_patterns=threat,
        )
        evidence_rows = compute_input_evidence(self.config.input_files)

        raw_matrix = self.flow_analyzer.get_communication_matrix()
        trimmed_matrix, matrix_note = trim_communication_matrix(
            raw_matrix,
            self.config.max_communication_matrix_ips,
        )

        comm_graph, comm_graph_meta = build_communication_graph(
            flows,
            assets_list,
            max_edges=self.config.max_communication_graph_edges,
        )

        if skip_topology:
            topology = NetworkTopology()
        else:
            self._user_status("Building network topology graph…")
            topology = TopologyBuilder(self.asset_tracker, self.flow_analyzer).build()

        if self.config.export_graph and not skip_topology:
            out_g = Path(self.config.export_graph)
            out_g.parent.mkdir(parents=True, exist_ok=True)
            self._user_status(f"Writing topology GraphML → {out_g.name}")
            topology.export_graphml(str(out_g))

        ended = perf_counter()
        metadata = {
            "tool": "luva",
            "version": __version__,
            "analysis_timestamp": started_at.isoformat(),
            "duration_seconds": round(ended - started, 3),
            "input_files": [str(p) for p in self.config.input_files],
            "total_packets": total_packets,
            "read_errors": read_errors,
            "analysis_mode": self.config.mode.value,
        }
        if self.config.report_filename_suffix:
            metadata["report_filename_suffix"] = self.config.report_filename_suffix
        if self.config.chunk_size > 0:
            metadata["max_packets_per_file"] = self.config.chunk_size
        if evidence_rows:
            metadata["input_evidence"] = evidence_rows
        metadata["evidence_integrity_note"] = (
            "SHA-256 is computed over each file as stored on disk (e.g. compressed bytes for .pcap.gz). "
            "Use for chain-of-custody; re-verify after copy or archival."
        )
        statistics = {
            "asset_stats": self.asset_tracker.stats,
            "flow_stats": self.flow_analyzer.stats,
            "protocol_distribution": self.flow_analyzer.get_protocol_distribution(),
            "top_talkers": self.flow_analyzer.get_top_talkers(25),
            "temporal_heatmap": self.flow_analyzer.get_temporal_heatmap(),
            "communication_matrix": trimmed_matrix,
            "communication_matrix_meta": matrix_note,
            "communication_graph": comm_graph,
            "communication_graph_meta": comm_graph_meta,
            "periodic_flows": self.flow_analyzer.detect_periodic_flows(),
            "top_flows_detailed": [f.to_dict() for f in self.flow_analyzer.get_top_flows(40)],
            "deep_survey": deep_dict,
            "pentest_insights": pentest,
            "threat_patterns": threat,
            "audit_workbook": audit_wb,
            "anomaly_stats": self.anomaly_engine.stats
            if not skip_anomaly
            else {
                "frames_processed": 0,
                "total_anomalies": 0,
                "severity_distribution": {},
                "rule_engine": {"total_rules": 0, "enabled_rules": 0, "severity_distribution": {}},
                "statistical_detector": self.anomaly_engine.stat_detector.stats,
            },
            "event_timeline": _build_event_timeline(anomalies),
        }

        self._user_status("Analysis pipeline finished — writing exports is next (CLI).")

        return AnalysisResult(
            metadata=metadata,
            assets=assets_list,
            flows=flows,
            topology=topology,
            anomalies=anomalies,
            statistics=statistics,
        )
