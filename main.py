"""Security log analyzer.

This script parses authentication logs and flags IP addresses with failed login attempts
that exceed a configurable threshold.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
import csv
from datetime import datetime, timedelta
from pathlib import Path
import json
import re
from typing import Iterable, Mapping

# Common patterns for failed logins. The analyzer looks for these first and then
# falls back to any line containing "fail" with an IP address.
FAILED_PATTERNS = [
    re.compile(r"Failed password .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"),
    re.compile(r"Failed login .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"),
    re.compile(r"Authentication failure.*rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"),
]

PASSWORD_SPRAY_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

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
    parser.add_argument(
        "--spray-min-users",
        type=int,
        default=5,
        help="Minimum distinct usernames per IP to flag password spraying (default: 5).",
    )
    parser.add_argument(
        "--spray-min-attempts",
        type=int,
        default=10,
        help="Minimum failed attempts per IP to flag password spraying (default: 10).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write a JSON or CSV report (use .json or .csv extension).",
    )
    return parser.parse_args()


def detect_password_spraying(
    lines: Iterable[str], *, min_users: int = 5, min_attempts: int = 10
) -> Mapping[str, dict[str, int]]:
    """Identify IPs that exhibit password spraying characteristics."""

    if min_users < 1:
        raise ValueError("Minimum users must be at least 1")
    if min_attempts < 1:
        raise ValueError("Minimum attempts must be at least 1")

    users_per_ip: defaultdict[str, set[str]] = defaultdict(set)
    attempts_per_ip: Counter[str] = Counter()

    for line in lines:
        match = PASSWORD_SPRAY_PATTERN.search(line)
        if not match:
            continue

        ip = match.group("ip")
        username = match.group("user")

        users_per_ip[ip].add(username)
        attempts_per_ip[ip] += 1

    return {
        ip: {"user_count": len(users_per_ip[ip]), "attempt_count": attempts}
        for ip, attempts in attempts_per_ip.items()
        if attempts >= min_attempts and len(users_per_ip[ip]) >= min_users
    }


def _build_report(
    *,
    flagged: Mapping[str, int],
    spray_suspects: Mapping[str, dict[str, int]],
    settings: Mapping[str, int | str],
) -> dict[str, object]:
    brute_force = [
        {"ip": ip, "failed_logins": count}
        for ip, count in sorted(flagged.items(), key=lambda item: item[1], reverse=True)
    ]

    password_spraying = [
        {
            "ip": ip,
            "attempt_count": stats["attempt_count"],
            "user_count": stats["user_count"],
        }
        for ip, stats in sorted(
            spray_suspects.items(), key=lambda item: item[1]["attempt_count"], reverse=True
        )
    ]

    return {
        "run_settings": settings,
        "brute_force": brute_force,
        "password_spraying": password_spraying,
        "top_offenders": brute_force,
    }


def _write_json_report(path: Path, report: Mapping[str, object]) -> None:
    path.write_text(json.dumps(report, indent=2))


def _write_csv_report(path: Path, report: Mapping[str, object]) -> None:
    with path.open("w", newline="") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=[
                "type",
                "field",
                "ip",
                "failed_logins",
                "attempt_count",
                "user_count",
                "value",
            ],
        )
        writer.writeheader()

        for key, value in report.get("run_settings", {}).items():
            writer.writerow({"type": "run_setting", "field": key, "value": value})

        for entry in report.get("brute_force", []):
            writer.writerow(
                {
                    "type": "brute_force",
                    "ip": entry.get("ip"),
                    "failed_logins": entry.get("failed_logins"),
                }
            )

        for entry in report.get("password_spraying", []):
            writer.writerow(
                {
                    "type": "password_spraying",
                    "ip": entry.get("ip"),
                    "attempt_count": entry.get("attempt_count"),
                    "user_count": entry.get("user_count"),
                }
            )

        for entry in report.get("top_offenders", []):
            writer.writerow(
                {
                    "type": "top_offender",
                    "ip": entry.get("ip"),
                    "failed_logins": entry.get("failed_logins"),
                }
            )


def _write_report(path: Path, report: Mapping[str, object]) -> None:
    if path.suffix.lower() == ".json":
        _write_json_report(path, report)
    elif path.suffix.lower() == ".csv":
        _write_csv_report(path, report)
    else:
        raise SystemExit("Unsupported output format. Use a .json or .csv extension.")


def main() -> None:
    args = _parse_args()
    if not args.log_file.is_file():
        raise SystemExit(f"Log file not found: {args.log_file}")

    lines = args.log_file.read_text().splitlines()

    flagged = analyze_log_file(
        lines,
        threshold=args.threshold,
        window_minutes=args.window_minutes,
        mode=args.mode,
    )

    spray_suspects = detect_password_spraying(
        lines,
        min_users=args.spray_min_users,
        min_attempts=args.spray_min_attempts,
    )

    report = _build_report(
        flagged=flagged,
        spray_suspects=spray_suspects,
        settings={
            "mode": args.mode,
            "threshold": args.threshold,
            "window_minutes": args.window_minutes,
            "spray_min_users": args.spray_min_users,
            "spray_min_attempts": args.spray_min_attempts,
        },
    )

    if flagged:
        print("Flagged IPs (failed logins >= threshold):")
        for entry in report["brute_force"]:
            ip = entry["ip"]
            count = entry["failed_logins"]
            print(f"- {ip}: {count} failed logins")
    else:
        print("No IP addresses exceeded the failed login threshold.")

    if spray_suspects:
        print("\nPassword spraying suspects:")
        for entry in report["password_spraying"]:
            ip = entry["ip"]
            attempts = entry["attempt_count"]
            users = entry["user_count"]
            print(f"- {ip}: {attempts} failed attempts across {users} usernames")
    else:
        print("\nNo password spraying suspects found.")

    if args.output:
        _write_report(args.output, report)


if __name__ == "__main__":
    main()
