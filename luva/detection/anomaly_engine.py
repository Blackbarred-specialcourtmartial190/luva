"""Anomaly engine — combines YAML rules and lightweight statistical checks."""

from __future__ import annotations

import logging
from pathlib import Path

from luva.core.config import Severity
from luva.detection.rule_engine import RuleEngine
from luva.detection.statistical import StatisticalDetector
from luva.models.event import AnomalyEvent
from luva.models.flow import NetworkFlow
from luva.parsers.base import ProtocolFrame

logger = logging.getLogger(__name__)


class AnomalyEngine:
    """Orchestrates rule-based and statistical detectors."""

    def __init__(self, min_severity: Severity = Severity.INFO):
        self.min_severity = min_severity
        self.rule_engine = RuleEngine()
        self.stat_detector = StatisticalDetector()

        self._all_events: list[AnomalyEvent] = []
        self._frames_processed: int = 0

    def load_rules(self, rules_dir: Path) -> int:
        """Load YAML rules from directory."""
        count = self.rule_engine.load_rules_from_dir(rules_dir)
        logger.info("Loaded %s anomaly rules", count)
        return count

    def process_frame(self, frame: ProtocolFrame) -> list[AnomalyEvent]:
        """Run all per-frame detectors; return events emitted for this frame (after severity filter)."""
        self._frames_processed += 1
        events = []

        rule_events = self.rule_engine.evaluate(frame)
        events.extend(rule_events)

        self.stat_detector.learn_from_frame(frame)

        pair_event = self.stat_detector.check_new_communication_pair(frame)
        if pair_event:
            events.append(pair_event)

        rare_event = self.stat_detector.check_rare_function_code(frame)
        if rare_event:
            events.append(rare_event)

        filtered = [e for e in events if e.severity >= self.min_severity]

        self._all_events.extend(filtered)
        return filtered

    def analyze_flows(self, flows: list[NetworkFlow]) -> list[AnomalyEvent]:
        """Flow-level statistical anomalies."""
        events = self.stat_detector.analyze_flows(flows)

        filtered = [e for e in events if e.severity >= self.min_severity]
        self._all_events.extend(filtered)

        logger.info("Flow analysis: %s anomalies recorded", len(filtered))
        return filtered

    def get_all_events(self) -> list[AnomalyEvent]:
        """All events collected in this run (sorted by severity score)."""
        return sorted(self._all_events, key=lambda e: e.severity_score, reverse=True)

    def get_events_by_severity(self, severity: Severity) -> list[AnomalyEvent]:
        """Filter by exact severity enum."""
        return [e for e in self._all_events if e.severity == severity]

    def get_critical_events(self) -> list[AnomalyEvent]:
        """CRITICAL severity only."""
        return self.get_events_by_severity(Severity.CRITICAL)

    @property
    def stats(self) -> dict:
        """Summary counters for reporting."""
        severity_counts: dict[str, int] = {}
        for event in self._all_events:
            sev = event.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "frames_processed": self._frames_processed,
            "total_anomalies": len(self._all_events),
            "severity_distribution": severity_counts,
            "rule_engine": self.rule_engine.get_rules_summary(),
            "statistical_detector": self.stat_detector.stats,
        }
