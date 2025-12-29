import sys
import textwrap
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parent.parent))

from main import analyze_log_file


def test_analyze_log_file_flags_ips_over_threshold():
    sample_log = textwrap.dedent(
        """
        Jan 10 12:00:00 server sshd[123]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
        Jan 10 12:00:05 server sshd[123]: Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
        Jan 10 12:01:00 server sshd[123]: Failed password for invalid user admin from 192.168.1.11 port 22 ssh2
        Jan 10 12:01:30 server sshd[123]: Failed login attempt from 10.0.0.5
        Jan 10 12:01:45 server sshd[123]: Failed login attempt from 10.0.0.5
        Jan 10 12:02:00 server sshd[123]: Failed login attempt from 10.0.0.5
        Jan 10 12:02:15 server sshd[123]: Accepted password for valid user from 10.0.0.5 port 22 ssh2
        Jan 10 12:02:30 server sshd[123]: Authentication failure for user from 172.16.0.2 rhost=172.16.0.2
        """
    ).strip().splitlines()

    flagged = analyze_log_file(sample_log, threshold=2)

    assert flagged == {
        "192.168.1.10": 2,
        "10.0.0.5": 3,
    }


def test_analyze_log_file_counts_single_failure_when_threshold_allows():
    sample_log = ["Authentication failure for user from 172.16.0.2 rhost=172.16.0.2"]

    flagged = analyze_log_file(sample_log, threshold=1, mode="total")

    assert flagged == {"172.16.0.2": 1}


def test_analyze_log_file_threshold_validation():
    with pytest.raises(ValueError):
        analyze_log_file([], threshold=0)


def test_rate_mode_respects_window():
    sample_log = textwrap.dedent(
        """
        Jan 10 12:00:00 server sshd[123]: Failed login attempt from 203.0.113.1
        Jan 10 12:03:00 server sshd[123]: Failed login attempt from 203.0.113.1
        Jan 10 12:03:30 server sshd[123]: Failed login attempt from 203.0.113.1
        """
    ).strip().splitlines()

    flagged = analyze_log_file(sample_log, threshold=2, window_minutes=2, mode="rate")

    assert flagged == {"203.0.113.1": 2}


def test_total_mode_ignores_time_window():
    sample_log = textwrap.dedent(
        """
        Jan 10 12:00:00 server sshd[123]: Failed login attempt from 198.51.100.8
        Jan 10 12:10:00 server sshd[123]: Failed login attempt from 198.51.100.8
        """
    ).strip().splitlines()

    flagged = analyze_log_file(sample_log, threshold=2, window_minutes=1, mode="total")

    assert flagged == {"198.51.100.8": 2}


def test_rate_mode_requires_valid_window():
    with pytest.raises(ValueError):
        analyze_log_file([], threshold=1, window_minutes=0, mode="rate")
