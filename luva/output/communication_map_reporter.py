"""Standalone interactive OT communication map (D3 force graph)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from luva.core.config import AnalysisConfig
from luva.core.pipeline import AnalysisResult
from luva.core.privacy import apply_export_privacy
from luva.output.export_names import suffixed_stem
from luva.output.vendor_scripts import read_embedded_script

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _json_for_script(obj: object) -> str:
    s = json.dumps(obj, ensure_ascii=False)
    return s.replace("<", "\\u003c")


class CommunicationMapReporter:
    """Write ``communication_map.html`` with embedded graph JSON."""

    def write(
        self,
        result: AnalysisResult,
        output_dir: Path,
        filename: str = "communication_map.html",
        export_config: Optional[AnalysisConfig] = None,
    ) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        stem = Path(filename).stem
        out_path = output_dir / f"{suffixed_stem(stem, export_config)}.html"

        graph = result.statistics.get("communication_graph") or {"nodes": [], "links": []}
        meta = result.statistics.get("communication_graph_meta") or {}
        payload: dict[str, Any] = {
            "metadata": dict(result.metadata),
            "graph": graph,
            "graph_meta": meta,
        }
        if export_config and (export_config.anonymize_ips or export_config.mask_payload):
            payload = apply_export_privacy(payload, export_config)

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("communication_map.html.j2")
        html = template.render(
            report_json=_json_for_script(payload),
            version=str(result.metadata.get("version", "")),
            d3_inline=read_embedded_script("d3.v7.min.js"),
        )
        out_path.write_text(html, encoding="utf-8")
        return out_path
