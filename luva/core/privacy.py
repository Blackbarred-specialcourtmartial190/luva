"""Export-time IP anonymization and payload redaction for reports."""

from __future__ import annotations

import copy
import hashlib
import re
from typing import Any

from luva.core.config import AnalysisConfig

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


def _pseudo_ip(seed: str) -> str:
    h = hashlib.sha256(seed.encode("utf-8")).digest()
    return f"10.{h[0]}.{h[1]}.{h[2]}"


def _build_ip_map(obj: Any, mapping: dict[str, str]) -> None:
    if isinstance(obj, dict):
        for v in obj.values():
            _build_ip_map(v, mapping)
    elif isinstance(obj, list):
        for v in obj:
            _build_ip_map(v, mapping)
    elif isinstance(obj, str):
        for m in _IPV4_RE.finditer(obj):
            ip = m.group(0)
            if ip not in mapping:
                mapping[ip] = _pseudo_ip(ip)


def _replace_ips(obj: Any, mapping: dict[str, str]) -> None:
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if isinstance(v, str):
                def repl(m: re.Match[str]) -> str:
                    return mapping.get(m.group(0), m.group(0))

                obj[k] = _IPV4_RE.sub(repl, v)
            else:
                _replace_ips(v, mapping)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str):
                def repl2(m: re.Match[str]) -> str:
                    return mapping.get(m.group(0), m.group(0))

                obj[i] = _IPV4_RE.sub(repl2, v)
            else:
                _replace_ips(v, mapping)


def anonymize_report_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy with IPv4 addresses replaced by deterministic 10.x.x.x pseudonyms."""
    out = copy.deepcopy(data)
    m: dict[str, str] = {}
    _build_ip_map(out, m)
    _replace_ips(out, m)
    return out


def mask_sensitive_payloads(data: dict[str, Any]) -> dict[str, Any]:
    """Redact obvious raw payload / hex blobs in nested structures."""
    out = copy.deepcopy(data)

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            for key in list(o.keys()):
                lk = str(key).lower()
                if lk in (
                    "raw_bytes",
                    "raw_payload",
                    "payload_hex",
                    "evidence_preview_hex",
                    "evidence_preview_ascii",
                    "http_context_excerpt",
                    "snmp_community_redacted",
                    "credential_hint_excerpt",
                ) and isinstance(o[key], str):
                    o[key] = "[REDACTED]"
                else:
                    walk(o[key])
        elif isinstance(o, list):
            for item in o:
                walk(item)

    walk(out)
    return out


def apply_export_privacy(data: dict[str, Any], config: AnalysisConfig) -> dict[str, Any]:
    """Apply configured privacy transforms to a report dictionary."""
    out = data
    if config.anonymize_ips:
        out = anonymize_report_dict(out)
    if config.mask_payload:
        out = mask_sensitive_payloads(out)
    return out
