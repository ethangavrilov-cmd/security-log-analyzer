import sys
import textwrap
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parent.parent))

from main import _build_report, _write_report, analyze_log_file, detect_password_spraying


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


def test_detect_password_spraying_flags_ip_with_many_usernames():
    sample_log = textwrap.dedent(
        """
        Jan 10 12:00:00 server sshd[123]: Failed password for invalid user alpha from 198.51.100.10 port 22 ssh2
        Jan 10 12:00:01 server sshd[123]: Failed password for invalid user beta from 198.51.100.10 port 22 ssh2
        Jan 10 12:00:02 server sshd[123]: Failed password for invalid user gamma from 198.51.100.10 port 22 ssh2
        Jan 10 12:00:03 server sshd[123]: Failed password for invalid user delta from 198.51.100.10 port 22 ssh2
        Jan 10 12:00:04 server sshd[123]: Failed password for invalid user epsilon from 198.51.100.10 port 22 ssh2
        Jan 10 12:00:05 server sshd[123]: Failed password for invalid user zeta from 198.51.100.10 port 22 ssh2
        Jan 10 12:00:06 server sshd[123]: Failed password for invalid user eta from 198.51.100.10 port 22 ssh2
        Jan 10 12:00:07 server sshd[123]: Failed password for invalid user theta from 198.51.100.10 port 22 ssh2
        Jan 10 12:00:08 server sshd[123]: Failed password for invalid user iota from 198.51.100.10 port 22 ssh2
        Jan 10 12:00:09 server sshd[123]: Failed password for invalid user kappa from 198.51.100.10 port 22 ssh2
        Jan 10 12:00:10 server sshd[123]: Failed password for root from 198.51.100.10 port 22 ssh2
        """
    ).strip().splitlines()

    suspects = detect_password_spraying(sample_log, min_users=5, min_attempts=10)

    assert suspects == {
        "198.51.100.10": {
            "attempt_count": 11,
            "user_count": 11,
        }
    }


def test_detect_password_spraying_requires_both_thresholds():
    sample_log = textwrap.dedent(
        """
        Jan 10 12:00:00 server sshd[123]: Failed password for invalid user alpha from 203.0.113.20 port 22 ssh2
        Jan 10 12:00:01 server sshd[123]: Failed password for invalid user beta from 203.0.113.20 port 22 ssh2
        Jan 10 12:00:02 server sshd[123]: Failed password for invalid user beta from 203.0.113.20 port 22 ssh2
        Jan 10 12:00:03 server sshd[123]: Failed password for invalid user beta from 203.0.113.20 port 22 ssh2
        Jan 10 12:00:04 server sshd[123]: Failed password for invalid user beta from 203.0.113.20 port 22 ssh2
        """
    ).strip().splitlines()

    suspects = detect_password_spraying(sample_log, min_users=3, min_attempts=5)

    assert suspects == {}


def test_detect_password_spraying_validates_thresholds():
    with pytest.raises(ValueError):
        detect_password_spraying([], min_users=0, min_attempts=1)

    with pytest.raises(ValueError):
        detect_password_spraying([], min_users=1, min_attempts=0)


def test_json_report_includes_all_sections(tmp_path: Path):
    report_path = tmp_path / "report.json"

    report = _build_report(
        flagged={"10.0.0.1": 3},
        spray_suspects={"10.0.0.2": {"attempt_count": 12, "user_count": 6}},
        settings={"mode": "rate", "threshold": 5, "window_minutes": 5, "spray_min_users": 5, "spray_min_attempts": 10},
    )

    _write_report(report_path, report)

    contents = report_path.read_text()
    assert "\"run_settings\"" in contents
    assert "\"brute_force\"" in contents
    assert "\"password_spraying\"" in contents
    assert "\"top_offenders\"" in contents


def test_csv_report_flattens_sections(tmp_path: Path):
    report_path = tmp_path / "report.csv"

    report = _build_report(
        flagged={"10.0.0.1": 2, "10.0.0.3": 5},
        spray_suspects={},
        settings={"mode": "total", "threshold": 2, "window_minutes": 1, "spray_min_users": 3, "spray_min_attempts": 7},
    )

    _write_report(report_path, report)

    rows = report_path.read_text().splitlines()
    assert rows[0].startswith("type,field,ip,failed_logins")
    assert any("run_setting,mode,," in row for row in rows)
    assert any("brute_force,,10.0.0.3,5" in row for row in rows)
    assert any("top_offender,,10.0.0.3,5" in row for row in rows)


def test_write_report_rejects_unknown_extension(tmp_path: Path):
    report = _build_report(
        flagged={},
        spray_suspects={},
        settings={},
    )

    with pytest.raises(SystemExit):
        _write_report(tmp_path / "report.txt", report)
