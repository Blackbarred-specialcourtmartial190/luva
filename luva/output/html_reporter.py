from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from luva.core.config import AnalysisConfig
from luva.core.pipeline import AnalysisResult
from luva.core.privacy import apply_export_privacy
from luva.output.baseline_embed_data import build_baseline_embed_bundle
from luva.output.export_names import suffixed_stem
from luva.output.vendor_scripts import read_embedded_script

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _json_for_script_tag(obj: object) -> str:
    """Serialize JSON for embedding in <script type=\"application/json\"> (XSS-safe)."""
    s = json.dumps(obj, ensure_ascii=False)
    return s.replace("<", "\\u003c")


class HTMLReporter:
    def write(
        self,
        result: AnalysisResult,
        output_dir: Path,
        filename: str = "analysis_report.html",
        export_config: Optional[AnalysisConfig] = None,
    ) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        stem = Path(filename).stem
        out_path = output_dir / f"{suffixed_stem(stem, export_config)}.html"
        payload = result.to_dict(export_config)
        if export_config and (export_config.anonymize_ips or export_config.mask_payload):
            payload = apply_export_privacy(payload, export_config)

        embed_bundle = build_baseline_embed_bundle(payload)
        baseline_embed_json = _json_for_script_tag(embed_bundle)
        baseline_soc_js = read_embedded_script("baseline_soc_embed.js") or ""

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("interactive_report.html.j2")
        html = template.render(
            metadata=payload["metadata"],
            report_json=_json_for_script_tag(payload),
            chart_js_inline=read_embedded_script("chart.umd.v4.min.js"),
            baseline_embed_json=baseline_embed_json,
            baseline_soc_js=baseline_soc_js,
        )
        out_path.write_text(html, encoding="utf-8")
        return out_path
