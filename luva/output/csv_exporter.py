from __future__ import annotations

import csv
from pathlib import Path
from typing import Optional

from luva.core.config import AnalysisConfig
from luva.core.pipeline import AnalysisResult
from luva.core.privacy import apply_export_privacy
from luva.output.export_names import suffixed_stem
from luva.models.asset import Asset
from luva.models.flow import NetworkFlow


class CSVExporter:
    def write(
        self,
        result: AnalysisResult,
        output_dir: Path,
        export_config: Optional[AnalysisConfig] = None,
    ) -> list[Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        outputs: list[Path] = []

        full = result.to_dict(export_config)
        if export_config and (export_config.anonymize_ips or export_config.mask_payload):
            full = apply_export_privacy(full, export_config)

        assets_path = output_dir / f"{suffixed_stem('assets', export_config)}.csv"
        with assets_path.open("w", encoding="utf-8", newline="") as f:
            assets = list(full.get("assets") or [])
            if assets:
                fieldnames = sorted({k for a in assets for k in a.keys()})
            else:
                fieldnames = sorted(Asset(ip_address="0.0.0.0").to_dict().keys())
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in assets:
                flat = dict(row)
                ec = flat.get("eks_components")
                if isinstance(ec, list):
                    flat["eks_components"] = ";".join(str(x) for x in ec)
                writer.writerow(flat)
        outputs.append(assets_path)

        ot_path = output_dir / f"{suffixed_stem('ot_assets', export_config)}.csv"
        with ot_path.open("w", encoding="utf-8", newline="") as f:
            ot_rows = list(full.get("ot_assets") or [])
            if ot_rows:
                fieldnames = sorted({k for row in ot_rows for k in row.keys()})
            else:
                fieldnames = [
                    "ip_address",
                    "role",
                    "ot_signals_summary",
                    "protocols_seen",
                    "open_ports",
                    "eks_components",
                    "risk_score",
                    "packet_count",
                ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in ot_rows:
                flat = dict(row)
                ec = flat.get("eks_components")
                if isinstance(ec, list):
                    flat["eks_components"] = ";".join(str(x) for x in ec)
                osigs = flat.get("ot_signals")
                if isinstance(osigs, list):
                    flat["ot_signals"] = ";".join(str(x) for x in osigs)
                for key in ("protocols_seen", "open_ports", "modbus_unit_ids", "communication_partners", "risk_factors"):
                    v = flat.get(key)
                    if isinstance(v, list):
                        flat[key] = ";".join(str(x) for x in v)
                writer.writerow(flat)
        outputs.append(ot_path)

        flows_path = output_dir / f"{suffixed_stem('flows', export_config)}.csv"
        with flows_path.open("w", encoding="utf-8", newline="") as f:
            flows = list(full.get("flows") or [])
            if flows:
                fieldnames = sorted({k for fl in flows for k in fl.keys()})
            else:
                dummy = NetworkFlow(
                    src_ip="0.0.0.0",
                    dst_ip="0.0.0.0",
                    src_port=0,
                    dst_port=0,
                    transport_protocol="TCP",
                )
                fieldnames = sorted(dummy.to_dict().keys())
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(flows)
        outputs.append(flows_path)

        anomalies_path = output_dir / f"{suffixed_stem('anomalies', export_config)}.csv"
        with anomalies_path.open("w", encoding="utf-8", newline="") as f:
            anomalies = list(full.get("anomalies") or [])
            fieldnames = (
                sorted({k for e in anomalies for k in e.keys()})
                if anomalies
                else ["event_id", "severity", "rule_id", "description"]
            )
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            if anomalies:
                writer.writerows(anomalies)
        outputs.append(anomalies_path)

        audit_path = output_dir / f"{suffixed_stem('audit_findings', export_config)}.csv"
        aw = full.get("statistics", {}).get("audit_workbook") or {}
        findings = list(aw.get("findings") or [])
        with audit_path.open("w", encoding="utf-8", newline="") as f:
            afn = [
                "finding_id",
                "severity",
                "category",
                "title",
                "narrative",
                "evidence_summary",
                "remediation",
                "mitre_attack_ids",
                "standards_refs",
            ]
            w = csv.DictWriter(f, fieldnames=afn)
            w.writeheader()
            for row in findings:
                mitre = row.get("mitre_attack_references") or []
                mids = ";".join(str(m.get("id", "")) for m in mitre if isinstance(m, dict))
                stds = row.get("standards_refs") or []
                std_join = ";".join(str(s) for s in stds) if isinstance(stds, list) else str(stds)
                w.writerow(
                    {
                        "finding_id": row.get("finding_id", ""),
                        "severity": row.get("severity", ""),
                        "category": row.get("category", ""),
                        "title": row.get("title", ""),
                        "narrative": row.get("narrative", ""),
                        "evidence_summary": row.get("evidence_summary", ""),
                        "remediation": row.get("remediation", ""),
                        "mitre_attack_ids": mids,
                        "standards_refs": std_join,
                    },
                )
        outputs.append(audit_path)

        return outputs
