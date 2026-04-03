"""Validate YAML rule files without loading them into a live engine."""

from __future__ import annotations

from pathlib import Path

import yaml

from luva.detection.rule_engine import rule_from_yaml_dict


def validate_rules_file(filepath: Path) -> list[str]:
    """Return human-readable errors for one YAML file (empty if OK)."""
    errors: list[str] = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"{filepath.name}: YAML error: {e}"]
    except OSError as e:
        return [f"{filepath.name}: cannot read: {e}"]

    if data is None:
        return [f"{filepath.name}: empty file"]
    if not isinstance(data, dict):
        return [f"{filepath.name}: root must be a mapping"]
    rules = data.get("rules")
    if rules is None:
        return [f"{filepath.name}: missing 'rules' list"]
    if not isinstance(rules, list):
        return [f"{filepath.name}: 'rules' must be a list"]

    for i, item in enumerate(rules):
        rid = "?"
        if isinstance(item, dict):
            rid = str(item.get("id", "?"))
        try:
            if not isinstance(item, dict):
                raise TypeError("rule entry must be a mapping")
            rule_from_yaml_dict(item)
        except (KeyError, TypeError, ValueError) as e:
            errors.append(f"{filepath.name}: rules[{i}] (id={rid}): {e}")
    return errors


def validate_rules_directory(rules_dir: Path) -> list[str]:
    """Validate every ``*.yaml`` in a directory."""
    if not rules_dir.exists():
        return [f"Directory not found: {rules_dir}"]
    if not rules_dir.is_dir():
        return [f"Not a directory: {rules_dir}"]

    all_errs: list[str] = []
    for yml in sorted(rules_dir.glob("*.yaml")):
        all_errs.extend(validate_rules_file(yml))
    return all_errs
