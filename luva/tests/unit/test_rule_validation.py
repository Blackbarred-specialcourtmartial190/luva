"""YAML rule directory validation (CLI ``validate-rules``)."""

from __future__ import annotations

from pathlib import Path

import yaml

from luva.detection.rule_validation import validate_rules_directory, validate_rules_file


def test_validate_builtin_rules_dir() -> None:
    rules = Path(__file__).resolve().parents[2] / "detection" / "rules"
    errs = validate_rules_directory(rules)
    assert errs == []


def test_validate_rejects_bad_rule(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        yaml.dump({"rules": [{"id": "x", "name": "n", "severity": "nope", "category": "PROTOCOL", "condition": {}}]}),
        encoding="utf-8",
    )
    errs = validate_rules_file(bad)
    assert errs
    assert "nope" in errs[0] or "severity" in errs[0].lower()
