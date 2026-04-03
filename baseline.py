#!/usr/bin/env python3
"""
OT/ICS behavioral baseline CLI.

Usage:
  python baseline.py --pcap capture.pcapng
  python baseline.py --pcap capture.pcapng -o ./baseline_run --baseline-dir ./baseline_out
"""

from __future__ import annotations

from ot_baseline.cli import run

if __name__ == "__main__":
    raise SystemExit(run())
