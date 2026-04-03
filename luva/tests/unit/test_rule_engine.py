"""Unit tests for YAML rule engine."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from luva.detection.rule_engine import RuleEngine
from luva.parsers.base import ProtocolFrame


def _modbus_broadcast_write_frame(**kwargs: object) -> ProtocolFrame:
    data = {
        "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 50000,
        "dst_port": 502,
        "protocol": "Modbus",
        "function_code": 0x06,
        "payload": {"unit_id": 255},
        "message_type": "request",
    }
    data.update(kwargs)
    return ProtocolFrame(**data)  # type: ignore[arg-type]


def test_modbus_broadcast_write_rule(tmp_path: Path) -> None:
    """MB-001 triggers on broadcast write-style frame."""
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        """
rules:
  - id: MB-001
    name: "Modbus Broadcast Write"
    description: "Write to broadcast unit id."
    severity: HIGH
    category: PROTOCOL
    condition:
      protocol: modbus
      function_code:
        in: [5, 6, 15, 16]
      unit_id: 255
    evidence_fields: [unit_id]
""",
        encoding="utf-8",
    )

    engine = RuleEngine()
    assert engine.load_rules_from_file(rules_file) == 1

    events = engine.evaluate(_modbus_broadcast_write_frame())
    assert len(events) == 1
    assert events[0].rule_id == "MB-001"
    assert events[0].evidence.get("unit_id") == 255


def test_protocol_mismatch_no_event() -> None:
    """Wrong protocol does not match Modbus-only rule."""
    rules_file = Path(__file__).resolve().parents[2] / "detection" / "rules" / "modbus_rules.yaml"
    engine = RuleEngine()
    engine.load_rules_from_file(rules_file)

    frame = _modbus_broadcast_write_frame(
        protocol="S7",
        function_code=0x29,
        payload={"unit_id": 255},
    )
    assert engine.evaluate(frame) == []
