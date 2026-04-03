from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer

from luva.core.config import ALL_EXPORT_FORMATS, AnalysisConfig, AnalysisMode, Severity, utc_report_filename_suffix
from luva.core.pipeline import AnalysisPipeline
from luva.detection.rule_validation import validate_rules_directory
from luva.output.communication_map_reporter import CommunicationMapReporter
from luva.output.csv_exporter import CSVExporter
from luva.output.html_reporter import HTMLReporter
from luva.output.json_reporter import JSONReporter
from luva.output.ndjson_anomalies import NdjsonAnomaliesReporter

# Plain Click-style help (no Rich panels/tables). Single top-level command — same as typer.run().
app = typer.Typer(
    add_completion=False,
    rich_markup_mode=None,
    pretty_exceptions_enable=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _parse_mode(value: str) -> AnalysisMode:
    normalized = value.strip().lower().replace("_", "-")
    for m in AnalysisMode:
        if m.value == normalized:
            return m
    raise typer.BadParameter(
        f"Invalid mode {value!r}. Use: full, anomaly-only, asset-only, topology-only.",
    )


def _parse_severity(value: str) -> Severity:
    key = value.strip().upper()
    try:
        return Severity[key]
    except KeyError as exc:
        raise typer.BadParameter(
            f"Invalid severity {value!r}. Use: INFO, LOW, MEDIUM, HIGH, CRITICAL.",
        ) from exc


def _parse_export_formats(value: Optional[str]) -> tuple[str, ...]:
    """Comma-separated export targets, or ``all``."""
    if value is None or not value.strip():
        return ALL_EXPORT_FORMATS
    raw = value.strip().lower()
    if raw == "all":
        return ALL_EXPORT_FORMATS
    parts = [p.strip().lower() for p in value.split(",") if p.strip()]
    allowed = set(ALL_EXPORT_FORMATS)
    for p in parts:
        if p not in allowed:
            raise typer.BadParameter(
                f"Unknown format {p!r}. Use: {', '.join(ALL_EXPORT_FORMATS)}, or all.",
            )
    seen: set[str] = set()
    ordered: list[str] = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    return tuple(ordered)


def _analyze(
    captures: list[Path],
    *,
    output_dir: Path,
    mode: AnalysisMode,
    min_severity: Severity,
    protocols: Optional[list[str]],
    custom_rules_dir: Optional[Path],
    anonymize_ips: bool,
    mask_payload: bool,
    export_graph: Optional[Path],
    show_progress: bool,
    verbose: bool,
    quiet: bool,
    report_filename_suffix: str,
    export_formats: tuple[str, ...],
    chunk_size: int,
    compare_baseline: Optional[Path],
    anomaly_subset_pcap: Optional[Path],
) -> None:
    log_level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s %(name)s: %(message)s", force=True)

    proto_list = protocols if protocols is not None else list(AnalysisConfig().protocols)

    config = AnalysisConfig(
        input_files=list(captures),
        output_dir=output_dir,
        mode=mode,
        min_severity=min_severity,
        protocols=proto_list,
        custom_rules_dir=custom_rules_dir,
        anonymize_ips=anonymize_ips,
        mask_payload=mask_payload,
        export_graph=export_graph,
        show_progress=show_progress,
        verbose=verbose,
        quiet=quiet,
        report_filename_suffix=report_filename_suffix,
        export_formats=export_formats,
        chunk_size=chunk_size,
        compare_baseline=compare_baseline,
        anomaly_subset_pcap=anomaly_subset_pcap,
    )

    issues = config.validate()
    if issues:
        for issue in issues:
            typer.secho(issue, err=True, fg=typer.colors.RED)
        raise typer.Exit(code=1)

    result = AnalysisPipeline(config).run()

    if config.compare_baseline is not None:
        import json

        from luva.analysis.baseline_diff import diff_analysis_reports

        prev = json.loads(config.compare_baseline.read_text(encoding="utf-8"))
        result.statistics["baseline_diff"] = diff_analysis_reports(prev, result.to_dict(export_config=None))

    if config.anomaly_subset_pcap is not None:
        from luva.output.anomaly_pcap_exporter import write_anomaly_subset_pcap

        n = write_anomaly_subset_pcap(
            list(config.input_files),
            result.anomalies,
            config.anomaly_subset_pcap,
            chunk_size=config.chunk_size,
        )
        if n:
            typer.echo(f"Anomaly subset PCAP: {n} packet(s) → {config.anomaly_subset_pcap.resolve()}")

    out = output_dir
    out.mkdir(parents=True, exist_ok=True)

    want = frozenset(config.export_formats)
    paths: list[Path] = []

    if not config.quiet:
        typer.echo("Writing exports…")

    if "json" in want:
        paths.append(JSONReporter().write(result, out, export_config=config))
    if "csv" in want:
        paths.extend(CSVExporter().write(result, out, export_config=config))
    if "html" in want:
        html_name = "analysis_report.html" if len(captures) > 1 else f"{captures[0].stem}.html"
        paths.append(HTMLReporter().write(result, out, filename=html_name, export_config=config))
    if "communication-map" in want:
        paths.append(CommunicationMapReporter().write(result, out, export_config=config))
    if "anomalies-ndjson" in want:
        paths.append(NdjsonAnomaliesReporter().write(result, out, export_config=config))

    typer.echo(f"Done. Output under {out.resolve()}/")
    for p in paths:
        if p.exists():
            typer.echo(f"  {p.resolve()}")
    tg = config.export_graph
    if tg and tg.exists():
        typer.echo(f"  {tg.resolve()}")


@app.command(no_args_is_help=True)
def main(
    captures: Annotated[
        list[Path],
        typer.Argument(help=".pcap / .pcapng / .gz capture file(s)."),
    ],
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", "-o", help="Directory for JSON, CSV, HTML, and GraphML."),
    ] = Path("reports"),
    mode: Annotated[
        str,
        typer.Option(
            "--mode",
            help="Analysis mode: full (default, all stages), anomaly-only, asset-only, topology-only.",
        ),
    ] = "full",
    min_severity: Annotated[
        str,
        typer.Option(
            "--min-severity",
            help="Minimum anomaly severity to record: INFO, LOW, MEDIUM, HIGH, CRITICAL.",
        ),
    ] = "INFO",
    protocols: Annotated[
        Optional[str],
        typer.Option(
            "--protocols",
            help="Comma-separated protocol slugs (e.g. modbus,s7). Default: all built-in parsers.",
        ),
    ] = None,
    custom_rules: Annotated[
        Optional[Path],
        typer.Option(
            "--custom-rules",
            help="Directory of additional YAML rule files (same schema as built-in rules).",
        ),
    ] = None,
    formats: Annotated[
        Optional[str],
        typer.Option(
            "--formats",
            help=(
                "Comma-separated outputs: json, csv, html, communication-map, anomalies-ndjson, "
                "or all (default)."
            ),
        ),
    ] = None,
    chunk_size: Annotated[
        int,
        typer.Option(
            "--chunk-size",
            help="Max packets to read per capture file (0 = full file).",
        ),
    ] = 0,
    compare_baseline: Annotated[
        Optional[Path],
        typer.Option(
            "--compare-baseline",
            help="Previous analysis_report.json to diff (adds statistics.baseline_diff to JSON).",
        ),
    ] = None,
    anomaly_subset_pcap: Annotated[
        Optional[Path],
        typer.Option(
            "--anomaly-subset-pcap",
            help="Write packets referenced by anomalies (packet_number + pcap_file) to this PCAP path.",
        ),
    ] = None,
    anonymize_ips: Annotated[
        bool,
        typer.Option("--anonymize-ips", help="Replace IPv4 addresses with deterministic pseudonyms in exports."),
    ] = False,
    mask_payload: Annotated[
        bool,
        typer.Option("--mask-payload", help="Redact raw payload / hex fields in exported JSON and reports."),
    ] = False,
    no_graph: Annotated[
        bool,
        typer.Option("--no-graph", help="Do not write topology GraphML."),
    ] = False,
    graph_path: Annotated[
        Optional[Path],
        typer.Option(
            "--graph-path",
            help="Base path for topology GraphML; a UTC run timestamp is appended before the extension.",
        ),
    ] = None,
    no_progress: Annotated[
        bool,
        typer.Option("--no-progress", help="Disable stderr packet progress."),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Verbose logging (INFO)."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="No stdout phase messages ([Luva] lines and export banner)."),
    ] = False,
) -> None:
    """Passive ICS/SCADA PCAP analysis.

    Defaults with no optional flags: **full** pipeline (``--mode full``), **all** built-in protocols,
    **all** export formats (json, csv, html, communication-map, anomalies-ndjson), topology GraphML,
    and **uncapped** report sizes (full matrices, graphs, and flow exports in JSON/HTML/CSV).
    Use ``--mode``, ``--formats``, ``--protocols``, ``--no-graph``, or ``AnalysisConfig`` limits to trim scope or size.
    """
    amode = _parse_mode(mode)
    sev = _parse_severity(min_severity)
    export_formats = _parse_export_formats(formats)
    report_suffix = utc_report_filename_suffix()

    proto_list: Optional[list[str]] = None
    if protocols is not None and protocols.strip():
        proto_list = [p.strip().lower() for p in protocols.split(",") if p.strip()]

    if no_graph:
        export_graph: Optional[Path] = None
    elif graph_path is not None:
        gp = graph_path
        export_graph = gp.parent / f"{gp.stem}{report_suffix}{gp.suffix}"
    else:
        export_graph = output_dir / f"topology{report_suffix}.graphml"

    _analyze(
        captures,
        output_dir=output_dir,
        mode=amode,
        min_severity=sev,
        protocols=proto_list,
        custom_rules_dir=custom_rules,
        anonymize_ips=anonymize_ips,
        mask_payload=mask_payload,
        export_graph=export_graph,
        show_progress=not no_progress,
        verbose=verbose,
        quiet=quiet,
        report_filename_suffix=report_suffix,
        export_formats=export_formats,
        chunk_size=chunk_size,
        compare_baseline=compare_baseline,
        anomaly_subset_pcap=anomaly_subset_pcap,
    )


def cli() -> None:
    """Console entry point for setuptools `[project.scripts]`."""
    if len(sys.argv) >= 2 and sys.argv[1] == "validate-rules":
        argv_rest = sys.argv[2:]
        if not argv_rest:
            typer.secho("Usage: luva validate-rules RULES_DIR", err=True, fg=typer.colors.RED)
            raise SystemExit(2)
        rules_dir = Path(argv_rest[0])
        errs = validate_rules_directory(rules_dir)
        for e in errs:
            typer.secho(e, err=True, fg=typer.colors.RED)
        if errs:
            raise SystemExit(1)
        typer.echo(f"OK — all rules valid under {rules_dir.resolve()}/")
        raise SystemExit(0)

    app()


def run_app() -> None:
    """Invoke the Typer CLI (used by `luva.py` and `python -m luva.cli.main`)."""
    cli()


if __name__ == "__main__":
    cli()
