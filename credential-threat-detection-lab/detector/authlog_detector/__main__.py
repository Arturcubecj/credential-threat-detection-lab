"""CLI: python -m authlog_detector <auth.log> [--allow 192.168.100.50] [--year 2026] [--json]"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime, timedelta

from .detector import DetectorConfig, detect
from .parser import parse_lines


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="authlog_detector", description=__doc__)
    p.add_argument("logfile", help="path to an sshd auth log, or - for stdin")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year for syslog timestamps")
    p.add_argument("--allow", action="append", default=[], help="IP or CIDR allowed to log in (repeatable)")
    p.add_argument("--window", type=int, default=60, help="sliding window in seconds")
    p.add_argument("--threshold", type=int, default=5, help="failures per window that raise a brute-force alert")
    p.add_argument("--json", action="store_true", help="print alerts as JSON lines")
    a = p.parse_args(argv)

    cfg = DetectorConfig(window=timedelta(seconds=a.window), brute_force_threshold=a.threshold, allowed_sources=a.allow)
    fh = sys.stdin if a.logfile == "-" else open(a.logfile, encoding="utf-8", errors="replace")
    with fh:
        alerts = detect(parse_lines(fh, a.year), cfg)
    for al in alerts:
        if a.json:
            print(json.dumps(asdict(al)))
        else:
            print(f"[{al.timestamp}] {al.rule:<30} sev={al.severity:<3} {al.mitre:<10} {al.src_ip:<16} user={al.user}  {al.detail}")
    return 1 if alerts else 0


if __name__ == "__main__":
    raise SystemExit(main())
