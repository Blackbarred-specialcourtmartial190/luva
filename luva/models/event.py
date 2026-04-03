"""Anomaly event model — structured detection output."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from luva.core.config import AnomalyCategory, Severity


@dataclass
class AnomalyEvent:
    """One detected anomaly or policy hit."""

    severity: Severity
    category: AnomalyCategory
    rule_id: str
    rule_name: str
    description: str

    event_id: str = field(default_factory=lambda: f"ANO-{uuid.uuid4().hex[:8].upper()}")
    timestamp: Optional[datetime] = None

    evidence: dict = field(default_factory=dict)
    affected_assets: list[str] = field(default_factory=list)
    confidence: float = 0.9
    tags: list[str] = field(default_factory=list)

    packet_number: Optional[int] = None
    pcap_file: Optional[str] = None

    @property
    def severity_score(self) -> int:
        """Numeric rank for sorting (1–10)."""
        _map = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 8,
            Severity.MEDIUM: 5,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }
        return _map.get(self.severity, 1)

    def to_dict(self) -> dict:
        """JSON-serializable dict."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "severity": self.severity.value,
            "severity_score": self.severity_score,
            "category": self.category.value,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "evidence": self.evidence,
            "affected_assets": self.affected_assets,
            "confidence": round(self.confidence, 2),
            "tags": self.tags,
            "packet_number": self.packet_number,
            "pcap_file": self.pcap_file,
        }
