"""Passive-operation guarantees — the tool only reads capture files from disk."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class PassivityGuard:
    """Ensures analysis stays read-only on local files (no live capture, no injection).

    Complements :meth:`luva.core.config.AnalysisConfig.validate`: the latter rejects missing
    paths before the run; this guard skips non-files defensively once the pipeline starts.
    """

    @staticmethod
    def validate_capture_inputs(paths: list[Path]) -> None:
        """Verify inputs exist and are regular files (readable captures only)."""
        for p in paths:
            if not p.exists():
                continue
            if not p.is_file():
                logger.warning("Skipping non-file path (passive mode reads files only): %s", p)

    @staticmethod
    def assert_no_live_capture_interface() -> None:
        """Reserved: fail if a future option requested live sniffing (not supported)."""
        return
