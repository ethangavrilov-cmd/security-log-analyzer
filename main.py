"""Security log analyzer.

This script parses authentication logs and flags IP addresses with failed login attempts
that exceed a configurable threshold.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
from datetime import datetime, timedelta
from pathlib import Path
import re
from typing import Iterable, Mapping

# Common patterns for failed logins. The analyzer looks for these first and then
# falls back to any line containing "fail" with an IP address.
FAILED_PATTERNS = [
    re.compile(r"Failed password .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"),
    re.compile(r"Failed login .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"),
    re.compile(r"Authentication failure.*rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"),
]

GENERIC_IP_PATTERN = re.compile(r"(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)")
TIMESTAMP_PATTERN = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def _extract_failed_ip(line: str) -> str | None:
    """Return the IP address from a failed login line, if present."""

    lower = line.lower()
    if "fail" not in lower:
        return None

    for pattern in FAILED_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group("ip")

    generic_match = GENERIC_IP_PATTERN.search(line)
    if generic_match:
        return generic_match.group("ip")

    return None


def _parse_timestamp(line: str) -> datetime | None:
    """Parse the timestamp prefix from a log line."""

    match = TIMESTAMP_PATTERN.match(line)
    if not match:
        return None

    try:
        return datetime.strptime(match.group("ts"), "%b %d %H:%M:%S")
    except ValueError:
        return None


def analyze_log_file(
    lines: Iterable[str],
    threshold: int,
    *,
    window_minutes: int = 5,
    mode: str = "rate",
) -> Mapping[str, int]:
    """Analyze log lines and return IPs that exceed the failed login threshold.

    Modes:
    - ``rate``: flag IPs with ``threshold`` or more failures within ``window_minutes``.
    - ``total``: flag IPs with ``threshold`` or more failures across the entire log.
    """

    if threshold < 1:
        raise ValueError("Threshold must be at least 1")
    if mode not in {"rate", "total"}:
        raise ValueError("Mode must be either 'rate' or 'total'")
    if mode == "rate" and window_minutes < 1:
        raise ValueError("Window minutes must be at least 1 when using rate mode")

    if mode == "total":
        failures: Counter[str] = Counter()
        for line in lines:
            ip = _extract_failed_ip(line)
            if ip:
                failures[ip] += 1
        return {ip: count for ip, count in failures.items() if count >= threshold}

    window = timedelta(minutes=window_minutes)
    windows: dict[str, deque[datetime]] = {}
    flagged: dict[str, int] = {}

    for line in lines:
        ip = _extract_failed_ip(line)
        if not ip:
            continue

        timestamp = _parse_timestamp(line)
        if not timestamp:
            continue

        ip_window = windows.setdefault(ip, deque())

        while ip_window and timestamp - ip_window[0] > window:
            ip_window.popleft()

        ip_window.append(timestamp)

        if len(ip_window) >= threshold:
            flagged[ip] = max(flagged.get(ip, 0), len(ip_window))

    return flagged


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze authentication logs for repeated failures.")
    parser.add_argument("log_file", type=Path, help="Path to the log file to analyze.")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Number of failed logins from an IP before it is flagged (default: 5).",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=5,
        help="Time window (in minutes) to evaluate failed login rates (default: 5).",
    )
    parser.add_argument(
        "--mode",
        choices=["total", "rate"],
        default="rate",
        help="Use 'rate' for time-window analysis or 'total' for overall counts.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if not args.log_file.is_file():
        raise SystemExit(f"Log file not found: {args.log_file}")

    flagged = analyze_log_file(
        args.log_file.read_text().splitlines(),
        threshold=args.threshold,
        window_minutes=args.window_minutes,
        mode=args.mode,
    )

    if not flagged:
        print("No IP addresses exceeded the failed login threshold.")
        return

    print("Flagged IPs (failed logins >= threshold):")
    for ip, count in sorted(flagged.items(), key=lambda item: item[1], reverse=True):
        print(f"- {ip}: {count} failed logins")


if __name__ == "__main__":
    main()
