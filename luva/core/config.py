"""Central analysis configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


def utc_report_filename_suffix() -> str:
    """UTC timestamp safe for filenames, e.g. ``_20260403_153045``."""
    return datetime.now(timezone.utc).strftime("_%Y%m%d_%H%M%S")


class AnalysisMode(str, Enum):
    """Analysis run modes."""
    FULL = "full"
    ANOMALY_ONLY = "anomaly-only"
    ASSET_ONLY = "asset-only"
    TOPOLOGY_ONLY = "topology-only"


class OutputFormat(str, Enum):
    """Report output formats."""
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    ALL = "all"


class Severity(str, Enum):
    """Anomaly severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def numeric(self) -> int:
        _map = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        }
        return _map[self.value]

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.numeric >= other.numeric

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.numeric > other.numeric

    def __le__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.numeric <= other.numeric

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.numeric < other.numeric


class AnomalyCategory(str, Enum):
    """Anomaly categories."""
    PROTOCOL = "PROTOCOL"
    BEHAVIOR = "BEHAVIOR"
    NETWORK = "NETWORK"
    POLICY = "POLICY"


# CLI / export: subset or "all" (handled in CLI before building config)
EXPORT_FORMAT_JSON = "json"
EXPORT_FORMAT_CSV = "csv"
EXPORT_FORMAT_HTML = "html"
EXPORT_FORMAT_COMMUNICATION_MAP = "communication-map"
EXPORT_FORMAT_ANOMALIES_NDJSON = "anomalies-ndjson"

ALL_EXPORT_FORMATS: tuple[str, ...] = (
    EXPORT_FORMAT_JSON,
    EXPORT_FORMAT_CSV,
    EXPORT_FORMAT_HTML,
    EXPORT_FORMAT_COMMUNICATION_MAP,
    EXPORT_FORMAT_ANOMALIES_NDJSON,
)


@dataclass
class AnalysisConfig:
    """Primary analysis configuration."""

    input_files: list[Path] = field(default_factory=list)

    mode: AnalysisMode = AnalysisMode.FULL
    protocols: list[str] = field(default_factory=lambda: [
        "modbus", "s7", "dnp3", "opcua", "enip", "iec104",
        "bacnet", "mqtt", "snmp", "omron_fins", "ge_srtp",
    ])

    output_format: OutputFormat = OutputFormat.JSON
    output_dir: Path = field(default_factory=lambda: Path("./results"))

    min_severity: Severity = Severity.INFO
    custom_rules_dir: Optional[Path] = None

    anonymize_ips: bool = False
    mask_payload: bool = False

    #: Max packets to read per input file (0 = entire capture). Useful for quick samples.
    chunk_size: int = 0
    #: Reserved for future memory-budget hints; not enforced by the pipeline today.
    max_memory_mb: int = 2048

    #: Report artifacts to write (see ALL_EXPORT_FORMATS). Ignored by the pipeline; CLI/reporters use this.
    export_formats: tuple[str, ...] = field(default_factory=lambda: ALL_EXPORT_FORMATS)

    #: Appended to report basenames before the extension (CLI sets :func:`utc_report_filename_suffix`). Empty = legacy names.
    report_filename_suffix: str = ""

    export_graph: Optional[Path] = None

    #: Previous ``analysis_report.json`` to diff against (new/removed assets, protocol deltas).
    compare_baseline: Optional[Path] = None

    #: Write packets referenced by anomalies (``packet_number`` + ``pcap_file``) into one PCAP.
    anomaly_subset_pcap: Optional[Path] = None

    #: Cap flows embedded in JSON/HTML/CSV exports (0 = no limit). Full analysis still uses all flows in RAM.
    #: Default 0 = export every flow (full reports); set lower for smaller artifacts.
    max_flows_export: int = 0
    #: Limit communication-matrix endpoints in reports (0 = no limit).
    max_communication_matrix_ips: int = 0

    #: Cap edges in ``communication_graph`` / map HTML (0 = no limit).
    max_communication_graph_edges: int = 0

    #: Log progress to stderr every N packets (0 = off). Single-threaded streaming read.
    show_progress: bool = True
    progress_packet_interval: int = 2_000_000

    quiet: bool = False
    verbose: bool = False
    log_level: str = "INFO"

    def validate(self) -> list[str]:
        """Validate configuration; return human-readable issues (empty if OK).

        File existence and extensions are checked here. The pipeline also calls
        :class:`luva.core.safety.PassivityGuard` before reading captures (defense in depth).
        """
        issues: list[str] = []

        allowed_exports = set(ALL_EXPORT_FORMATS)
        for fmt in self.export_formats:
            if fmt not in allowed_exports:
                issues.append(f"Unknown export format {fmt!r}. Use: {', '.join(ALL_EXPORT_FORMATS)}.")

        if not self.export_formats:
            issues.append("export_formats must include at least one format.")

        if not self.input_files:
            issues.append("No input capture files. Provide at least one .pcap, .pcapng, or .gz file.")

        if self.chunk_size < 0:
            issues.append("chunk_size must be >= 0 (0 = read entire capture).")

        for f in self.input_files:
            if not f.exists():
                issues.append(f"Input file not found: {f}")
            elif f.suffix.lower() not in (".pcap", ".pcapng", ".gz"):
                issues.append(f"Unsupported file extension: {f.suffix}")

        if self.custom_rules_dir and not self.custom_rules_dir.is_dir():
            issues.append(f"Custom rules directory not found: {self.custom_rules_dir}")

        if self.compare_baseline is not None:
            if not self.compare_baseline.is_file():
                issues.append(f"Baseline report not found: {self.compare_baseline}")

        return issues


# Default well-known port → protocol slug hints
DEFAULT_PORT_PROTOCOL_MAP: dict[int, str] = {
    502: "modbus",
    102: "s7",
    20000: "dnp3",
    4840: "opcua",
    44818: "enip",
    2222: "enip",
    2404: "iec104",
    47808: "bacnet",
    9600: "omron_fins",
    18245: "ge_srtp",
    18246: "ge_srtp",
    1883: "mqtt",
    8883: "mqtt",
    161: "snmp",
    162: "snmp",
}

# Protocol slug → default well-known ports
PROTOCOL_DEFAULT_PORTS: dict[str, list[int]] = {
    "modbus": [502],
    "s7": [102],
    "dnp3": [20000],
    "opcua": [4840],
    "enip": [44818, 2222],
    "iec104": [2404],
    "bacnet": [47808],
    "omron_fins": [9600],
    "ge_srtp": [18245, 18246],
    "mqtt": [1883, 8883, 8884, 9001],
    "snmp": [161, 162],
}
