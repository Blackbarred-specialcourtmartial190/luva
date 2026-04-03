"""Consistent report filenames with optional UTC run suffix."""

from __future__ import annotations

from typing import Optional

from luva.core.config import AnalysisConfig


def suffixed_stem(base: str, export_config: Optional[AnalysisConfig]) -> str:
    """Return ``base`` + ``report_filename_suffix`` when set on config (e.g. ``_20260403_153045``)."""
    suf = ""
    if export_config is not None:
        suf = export_config.report_filename_suffix or ""
    return f"{base}{suf}"
