"""Extract raw packets that triggered anomalies into a small PCAP (second pass, streaming)."""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, DefaultDict, List, Set, cast

from luva.core.exceptions import PCAPReadError, PCAPValidationError
from luva.engine.pcap_reader import PCAPReader
from luva.models.event import AnomalyEvent

logger = logging.getLogger(__name__)


def write_anomaly_subset_pcap(
    input_files: list[Path],
    anomalies: list[AnomalyEvent],
    output_path: Path,
    *,
    chunk_size: int = 0,
) -> int:
    """Write one merged PCAP containing packets referenced by anomalies.

    Matches on ``(pcap_file basename, packet_number)``. Events without both are skipped.
    Re-reads captures with Scapy (streaming). Returns number of packets written.
    """
    wanted: DefaultDict[str, Set[int]] = defaultdict(set)
    for e in anomalies:
        if e.packet_number is None or not e.pcap_file:
            continue
        wanted[e.pcap_file].add(e.packet_number)

    if not wanted:
        logger.info("No anomalies with packet_number and pcap_file — skipping subset PCAP")
        return 0

    collected: List[Any] = []
    for cap in input_files:
        name = cap.name
        nums = wanted.get(name)
        if not nums:
            continue
        try:
            reader = PCAPReader(cap)
        except (PCAPValidationError, PCAPReadError) as exc:
            logger.warning("Skipping %s for anomaly PCAP: %s", cap, exc)
            continue

        cs = chunk_size if chunk_size > 0 else 0
        try:
            for pkt_num, raw_pkt in reader.iter_scapy_packets(chunk_size=cs):
                if pkt_num in nums:
                    collected.append(raw_pkt)
        except PCAPReadError as exc:
            logger.warning("Read failed for anomaly PCAP slice %s: %s", cap, exc)
            continue

    if not collected:
        logger.warning("No matching packets found for anomaly subset PCAP")
        return 0

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    from scapy.all import wrpcap  # type: ignore[attr-defined]

    wrpcap(str(output_path), cast(Any, collected))
    return len(collected)
