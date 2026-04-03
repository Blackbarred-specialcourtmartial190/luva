"""Bundled JS for offline HTML (D3, Chart.js) with CDN fallback in templates."""

from __future__ import annotations

from pathlib import Path

_STATIC_DIR = Path(__file__).resolve().parent / "static"


def read_embedded_script(filename: str, *, min_bytes: int = 500) -> str | None:
    """Return file contents if present and large enough; else None (use CDN in template)."""
    path = _STATIC_DIR / filename
    try:
        if path.is_file() and path.stat().st_size >= min_bytes:
            return path.read_text(encoding="utf-8")
    except OSError:
        pass
    return None
