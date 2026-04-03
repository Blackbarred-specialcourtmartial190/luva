"""Tests for export-time privacy helpers."""

from __future__ import annotations

from luva.core.privacy import anonymize_report_dict, mask_sensitive_payloads


def test_anonymize_report_dict_replaces_ipv4() -> None:
    data = {
        "assets": [{"ip_address": "192.168.1.1", "communication_partners": ["192.168.1.2"]}],
        "metadata": {"note": "host 192.168.1.1 talks to 192.168.1.2"},
    }
    out = anonymize_report_dict(data)
    assert out["assets"][0]["ip_address"].startswith("10.")
    assert out["assets"][0]["ip_address"] != "192.168.1.1"
    assert "192.168.1.1" not in str(out)


def test_mask_payload_redacts_ot_cleartext_previews() -> None:
    data = {
        "statistics": {
            "deep_survey": {
                "cleartext_ot_sensitive": {
                    "samples": [
                        {
                            "evidence_preview_hex": "deadbeef",
                            "snmp_community_redacted": "p***c",
                            "http_context_excerpt": "GET /plc",
                        }
                    ]
                }
            }
        }
    }
    out = mask_sensitive_payloads(data)
    s0 = out["statistics"]["deep_survey"]["cleartext_ot_sensitive"]["samples"][0]
    assert s0["evidence_preview_hex"] == "[REDACTED]"
    assert s0["snmp_community_redacted"] == "[REDACTED]"
    assert s0["http_context_excerpt"] == "[REDACTED]"
