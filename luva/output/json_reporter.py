from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from luva.core.config import AnalysisConfig
from luva.core.pipeline import AnalysisResult
from luva.core.privacy import apply_export_privacy
from luva.output.export_names import suffixed_stem


class JSONReporter:
    def write(
        self,
        result: AnalysisResult,
        output_dir: Path,
        export_config: Optional[AnalysisConfig] = None,
    ) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        out_path = output_dir / f"{suffixed_stem('analysis_report', export_config)}.json"
        payload = result.to_dict(export_config)
        if export_config and (export_config.anonymize_ips or export_config.mask_payload):
            payload = apply_export_privacy(payload, export_config)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return out_path
