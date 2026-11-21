from datetime import timedelta
from pathlib import Path

from authlog_detector import DetectorConfig, detect, parse_line, parse_lines

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
CFG = DetectorConfig(allowed_sources=["192.168.100.50/32"])


def _load(name):
    with open(SAMPLES / name, encoding="utf-8") as fh:
        return list(parse_lines(fh, 2026))


def test_parser_failed_invalid_user():
    ev = parse_line("Nov 20 10:05:20 victim sshd[1301]: Failed password for invalid user admin from 192.168.100.10 port 50200 ssh2", 2026)
    assert ev.outcome == "failure" and ev.user == "admin" and ev.invalid_user and ev.src_ip == "192.168.100.10"


def test_parser_accepted_publickey():
    ev = parse_line("Nov 20 09:58:11 victim sshd[1101]: Accepted publickey for labadmin from 192.168.100.50 port 51234 ssh2", 2026)
    assert ev.outcome == "success" and ev.method == "publickey"


def test_parser_ignores_other_lines():
    assert parse_line("Nov 20 10:05:20 victim sshd[1301]: Invalid user admin from 192.168.100.10 port 50200", 2026) is None
    assert parse_line("# comment", 2026) is None


def test_round1_raises_expected_alerts():
    rules = [a.rule for a in detect(_load("auth_round1_synthetic.log"), CFG)]
    assert rules.count("ssh_brute_force") == 1
    assert "ssh_password_spraying" in rules
    assert "ssh_success_after_failures" in rules
    assert "ssh_login_unauthorized_source" in rules


def test_admin_login_from_allowlist_is_quiet():
    alerts = detect(_load("auth_round1_synthetic.log"), CFG)
    assert all(a.src_ip != "192.168.100.50" for a in alerts)


def test_round2_detects_attempts_but_no_compromise():
    rules = {a.rule for a in detect(_load("auth_round2_synthetic.log"), CFG)}
    assert rules == {"ssh_brute_force"}


def test_threshold_is_configurable():
    events = _load("auth_round1_synthetic.log")
    strict = DetectorConfig(brute_force_threshold=10, window=timedelta(seconds=30), allowed_sources=["192.168.100.50/32"])
    assert "ssh_brute_force" not in {a.rule for a in detect(events, strict)}
