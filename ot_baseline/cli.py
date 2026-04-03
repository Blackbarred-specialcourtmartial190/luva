"""
Command-line entry: stream PCAP, run analyzers, emit JSON + summary.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from ot_baseline.analyzer.baseline_compare import BaselineComparator
from ot_baseline.analyzer.commands import CommandProfileAnalyzer
from ot_baseline.analyzer.communication import CommunicationAnalyzer
from ot_baseline.analyzer.protocols import ProtocolAnalyzer
from ot_baseline.analyzer.temporal import TemporalAnalyzer
from ot_baseline.analyzer.traffic import TrafficAnalyzer
from ot_baseline.parser.stream import iter_packet_records
from ot_baseline.reporter.emit import write_json, write_summary_text

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format=LOG_FORMAT, stream=sys.stderr, force=True)


def _meta(pcap: Path) -> dict:
    return {
        "tool": "ot_baseline",
        "version": "0.1.0",
        "pcap_path": str(pcap.resolve()),
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build OT/ICS behavioral baseline artifacts from an offline PCAP (Scapy stream).",
    )
    parser.add_argument(
        "--pcap",
        required=True,
        type=Path,
        help="Path to .pcap / .pcapng (offline capture).",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("baseline_out"),
        help="Directory for JSON reports and summary.txt (default: ./baseline_out).",
    )
    parser.add_argument(
        "--baseline-dir",
        type=Path,
        default=None,
        help="Optional directory with a previous run's JSON files for delta comparison.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="DEBUG logging.",
    )
    parser.add_argument(
        "--max-payload",
        type=int,
        default=4096,
        help="Max TCP/UDP payload bytes stored per packet for Modbus parsing (default: 4096).",
    )
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)
    log = logging.getLogger("ot_baseline")

    pcap = args.pcap
    if not pcap.is_file():
        log.error("PCAP does not exist: %s", pcap)
        return 2

    out = args.output_dir
    comm_a = CommunicationAnalyzer()
    proto_a = ProtocolAnalyzer()
    traffic_a = TrafficAnalyzer()
    cmd_a = CommandProfileAnalyzer()
    temporal_a = TemporalAnalyzer()
    comparator = BaselineComparator(args.baseline_dir)

    n = 0
    try:
        for rec in iter_packet_records(pcap, max_payload_capture=args.max_payload):
            comm_a.consume(rec)
            proto_a.consume(rec)
            traffic_a.consume(rec)
            cmd_a.consume(rec)
            temporal_a.consume(rec)
            n += 1
            if n % 500_000 == 0:
                log.info("Processed %s packets…", f"{n:,}")
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 2
    except RuntimeError as exc:
        log.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        log.warning("Interrupted after %s packets", n)
        return 130

    log.info("Finished reading %s IP packets.", f"{n:,}")

    comm = comm_a.to_dict()
    comm["meta"] = _meta(pcap)
    proto = proto_a.to_dict()
    proto["meta"] = _meta(pcap)
    traffic = traffic_a.to_dict()
    traffic["meta"] = _meta(pcap)
    traffic["temporal_behavior"] = temporal_a.to_dict()
    cmd = cmd_a.to_dict()
    cmd["meta"] = _meta(pcap)

    baseline_delta = comparator.diff(comm, traffic, cmd)
    comm["baseline_comparison"] = baseline_delta

    write_json(out / "communication_map.json", comm)
    write_json(out / "protocol_distribution.json", proto)
    write_json(out / "traffic_profile.json", traffic)
    write_json(out / "command_profile.json", cmd)
    write_summary_text(
        out / "summary.txt",
        pcap=pcap,
        comm=comm,
        proto=proto,
        traffic=traffic,
        cmd=cmd,
        baseline=baseline_delta,
    )

    log.info("Outputs written under %s", out.resolve())
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
