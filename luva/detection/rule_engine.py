"""YAML rule engine — load and evaluate anomaly rules from disk."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from luva.core.config import Severity, AnomalyCategory
from luva.core.exceptions import RuleLoadError
from luva.models.event import AnomalyEvent
from luva.parsers.base import ProtocolFrame

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    """Single anomaly detection rule."""
    id: str
    name: str
    description: str
    severity: Severity
    category: AnomalyCategory
    condition: dict
    confidence: float = 0.9
    tags: list[str] = field(default_factory=list)
    evidence_fields: list[str] = field(default_factory=list)
    enabled: bool = True


def rule_from_yaml_dict(data: dict) -> Rule:
    """Build a :class:`Rule` from one YAML rule mapping; raise on invalid schema."""
    if not isinstance(data, dict):
        raise TypeError("rule must be a mapping")
    return Rule(
        id=data["id"],
        name=data["name"],
        description=data.get("description", ""),
        severity=Severity(data["severity"]),
        category=AnomalyCategory(data["category"]),
        condition=data["condition"],
        confidence=float(data.get("confidence", 0.9)),
        tags=list(data.get("tags", [])),
        evidence_fields=list(data.get("evidence_fields", [])),
        enabled=bool(data.get("enabled", True)),
    )


class RuleEngine:
    """YAML-based anomaly rule engine: load rules and evaluate protocol frames."""

    def __init__(self):
        self._rules: list[Rule] = []
        self._rule_map: dict[str, Rule] = {}

    def load_rules_from_dir(self, rules_dir: Path) -> int:
        """Load every `*.yaml` in a directory.

        Returns:
            Number of rules appended.
        """
        count = 0
        if not rules_dir.exists():
            logger.warning("Rules directory not found: %s", rules_dir)
            return 0

        for yaml_file in sorted(rules_dir.glob("*.yaml")):
            try:
                loaded = self.load_rules_from_file(yaml_file)
                count += loaded
                logger.info("Loaded %s (%s rules)", yaml_file.name, loaded)
            except RuleLoadError as e:
                logger.error("Rule load error %s: %s", yaml_file.name, e)

        return count

    def load_rules_from_file(self, filepath: Path) -> int:
        """Load rules from one YAML file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except (yaml.YAMLError, OSError) as e:
            raise RuleLoadError(f"YAML read error: {e}", {"file": str(filepath)})

        if not data or "rules" not in data:
            return 0

        count = 0
        for rule_data in data["rules"]:
            try:
                rule = rule_from_yaml_dict(rule_data)
                self._rules.append(rule)
                self._rule_map[rule.id] = rule
                count += 1
            except (KeyError, ValueError) as e:
                logger.warning("Skipped invalid rule (%s): %s", filepath.name, e)

        return count

    def evaluate(self, frame: ProtocolFrame) -> list[AnomalyEvent]:
        """Evaluate frame against all enabled rules.

        Returns:
            List of triggered anomaly events.
        """
        events = []

        for rule in self._rules:
            if not rule.enabled:
                continue

            try:
                if self._matches(rule, frame):
                    event = self._create_event(rule, frame)
                    events.append(event)
            except (TypeError, ValueError, KeyError, AttributeError, IndexError) as e:
                logger.debug("Rule evaluation error (%s): %s", rule.id, e)
            except Exception as e:
                logger.warning("Unexpected rule evaluation error (%s): %s", rule.id, e)
                logger.debug("Rule evaluation traceback", exc_info=True)

        return events

    def _matches(self, rule: Rule, frame: ProtocolFrame) -> bool:
        """True if frame satisfies rule.condition."""
        condition = rule.condition

        # Protocol (YAML uses slug: modbus, s7, opcua, …)
        if "protocol" in condition:
            rule_p = str(condition["protocol"]).lower()
            frame_p = (frame.protocol_slug or frame.protocol.lower().replace(" ", "").replace("/", "")).lower()
            if frame_p != rule_p:
                return False

        # Function code
        if "function_code" in condition:
            fc_cond = condition["function_code"]

            if isinstance(fc_cond, int):
                if frame.function_code != fc_cond:
                    return False
            elif isinstance(fc_cond, dict):
                if "in" in fc_cond:
                    if frame.function_code not in fc_cond["in"]:
                        return False
                if "range" in fc_cond:
                    r = fc_cond["range"]
                    if not (r[0] <= (frame.function_code or -1) <= r[1]):
                        return False
                if "not_in" in fc_cond:
                    if frame.function_code in fc_cond["not_in"]:
                        return False

        # Modbus unit ID
        if "unit_id" in condition:
            payload_uid = frame.payload.get("unit_id")
            if payload_uid != condition["unit_id"]:
                return False

        # Message type
        if "message_type" in condition:
            if frame.message_type != condition["message_type"]:
                return False

        # S7 service / function code
        if "service_code" in condition:
            svc_cond = condition["service_code"]
            s7_fc = frame.payload.get("s7_function_code", frame.function_code)

            if isinstance(svc_cond, int):
                if s7_fc != svc_cond:
                    return False
            elif isinstance(svc_cond, dict):
                if "in" in svc_cond:
                    if s7_fc not in svc_cond["in"]:
                        return False

        # Payload field predicates
        if "payload_field" in condition:
            pf = condition["payload_field"]
            field_name = pf.get("name")
            if field_name:
                value = frame.payload.get(field_name)
                if "equals" in pf and value != pf["equals"]:
                    return False
                if "greater_than" in pf and (value is None or value <= pf["greater_than"]):
                    return False
                if "less_than" in pf and (value is None or value >= pf["less_than"]):
                    return False

        return True

    def _create_event(self, rule: Rule, frame: ProtocolFrame) -> AnomalyEvent:
        """Build AnomalyEvent from matched rule + frame."""
        # Evidence payload
        evidence = {
            "src_ip": frame.src_ip,
            "dst_ip": frame.dst_ip,
            "protocol": frame.protocol,
        }

        if frame.function_code is not None:
            evidence["function_code"] = f"0x{frame.function_code:02X}"
            evidence["function_name"] = frame.function_name or ""

        # Optional extra evidence keys from rule
        for field_name in rule.evidence_fields:
            if field_name in frame.payload:
                evidence[field_name] = frame.payload[field_name]

        description = (
            f"{rule.description} — "
            f"{frame.src_ip} → {frame.dst_ip} "
            f"({frame.protocol}"
            f"{', FC=0x' + format(frame.function_code, '02X') if frame.function_code is not None else ''})"
        )

        return AnomalyEvent(
            severity=rule.severity,
            category=rule.category,
            rule_id=rule.id,
            rule_name=rule.name,
            description=description,
            timestamp=frame.timestamp,
            evidence=evidence,
            affected_assets=[frame.src_ip, frame.dst_ip],
            confidence=rule.confidence,
            tags=rule.tags,
            packet_number=frame.packet_number,
            pcap_file=frame.pcap_file,
        )

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def get_rules_summary(self) -> dict:
        """Counts for loaded rules."""
        severity_counts: dict[str, int] = {}
        for rule in self._rules:
            sev = rule.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_rules": self.rule_count,
            "enabled_rules": sum(1 for r in self._rules if r.enabled),
            "severity_distribution": severity_counts,
        }
