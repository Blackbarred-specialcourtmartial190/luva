"""AnomalyEngine accepts frames and returns a list (rules may be empty)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from luva.core.config import Severity
from luva.detection.anomaly_engine import AnomalyEngine
from luva.parsers.base import ProtocolFrame


def test_process_frame_returns_list() -> None:
    eng = AnomalyEngine(min_severity=Severity.INFO)
    frame = ProtocolFrame(
        timestamp=datetime.now(timezone.utc),
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=40000,
        dst_port=502,
        protocol="Modbus",
        protocol_slug="modbus",
        function_code=3,
    )
    out = eng.process_frame(frame)
    assert isinstance(out, list)
    assert eng.stats["frames_processed"] == 1


def test_load_rules_from_built_in_dir() -> None:
    rules_dir = Path(__file__).resolve().parents[2] / "detection" / "rules"
    eng = AnomalyEngine()
    n = eng.load_rules(rules_dir)
    assert n > 0
    summary = eng.rule_engine.get_rules_summary()
    assert summary["total_rules"] > 0
