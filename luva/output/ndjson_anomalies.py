"""One JSON object per line for SIEM-style anomaly ingestion."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from luva.core.config import AnalysisConfig
from luva.core.pipeline import AnalysisResult
from luva.core.privacy import apply_export_privacy
from luva.output.export_names import suffixed_stem


class NdjsonAnomaliesReporter:
    """Write ``anomalies.ndjson`` — one anomaly record per line."""

    def write(
        self,
        result: AnalysisResult,
        output_dir: Path,
        filename: str = "anomalies.ndjson",
        export_config: Optional[AnalysisConfig] = None,
    ) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        stem = Path(filename).stem
        out_path = output_dir / f"{suffixed_stem(stem, export_config)}.ndjson"
        with out_path.open("w", encoding="utf-8") as f:
            for event in result.anomalies:
                row = event.to_dict()
                if export_config and (export_config.anonymize_ips or export_config.mask_payload):
                    row = apply_export_privacy({"_": row}, export_config)["_"]
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        return out_path
