from datetime import UTC, datetime

import pytest

from soclab.ingest import parse_lines
from soclab.ingest.parsers import parse_linux_auth, parse_ufw

FAILED = (
    "Oct 20 09:14:03 web01 sshd[4242]: Failed password for root from 203.0.113.66 port 51122 ssh2"
)
INVALID = (
    "Oct  5 09:14:03 web01 sshd[4242]: "
    "Failed password for invalid user oracle from 198.51.100.77 port 40000 ssh2"
)
ACCEPTED = (
    "Oct 20 09:15:00 web01 sshd[4250]: Accepted publickey for alice from 10.10.0.20 port 50000 ssh2"
)
UFW = (
    "Oct 20 09:00:01 web01 kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e "
    "SRC=203.0.113.200 DST=10.0.0.5 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=1 PROTO=TCP "
    "SPT=40000 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0"
)


def test_failed_login_fields():
    e = parse_linux_auth(FAILED, 2026)
    assert e.outcome == "failure"
    assert e.user_name == "root"
    assert e.source_ip == "203.0.113.66"
    assert e.source_port == 51122
    assert e.host_name == "web01"
    assert e.timestamp == datetime(2026, 10, 20, 9, 14, 3, tzinfo=UTC)


def test_invalid_user_and_space_padded_day():
    e = parse_linux_auth(INVALID, 2026)
    assert e.user_name == "oracle"
    assert e.timestamp.day == 5


def test_accepted_login():
    e = parse_linux_auth(ACCEPTED, 2026)
    assert e.outcome == "success"
    assert e.user_name == "alice"


def test_rfc3339_timestamp_newer_ubuntu():
    line = FAILED.replace("Oct 20 09:14:03", "2026-10-20T11:14:03.123456+02:00")
    assert parse_linux_auth(line, 1999).timestamp == datetime(
        2026, 10, 20, 9, 14, 3, 123456, tzinfo=UTC
    )


def test_log_injection_in_username_cannot_spoof_source_ip():
    # Attacker picks a username containing a fake "from <victim ip>" clause.
    line = (
        "Oct 20 09:14:03 web01 sshd[1]: Failed password for invalid user "
        "x from 10.10.0.20 port 22 from 203.0.113.66 port 51122 ssh2"
    )
    e = parse_linux_auth(line, 2026)
    assert e.source_ip == "203.0.113.66"  # the address sshd itself appended


@pytest.mark.parametrize(
    "line",
    [
        "Oct 20 09:15:00 web01 sshd[4250]: pam_unix(sshd:session): session opened for user alice",
        "Oct 20 09:15:00 web01 CRON[99]: (root) CMD (run-parts /etc/cron.hourly)",
    ],
)
def test_irrelevant_lines_are_ignored(line):
    assert parse_linux_auth(line, 2026) is None


def test_ufw_block_fields():
    e = parse_ufw(UFW, 2026)
    assert e.event_action == "firewall_block"
    assert (e.source_ip, e.destination_ip, e.destination_port) == ("203.0.113.200", "10.0.0.5", 22)
    assert e.network_transport == "tcp"


def test_parse_lines_counts_instead_of_crashing():
    lines = [
        FAILED,
        "complete garbage",
        FAILED.replace("203.0.113.66", "999.1.1.1"),  # invalid IP
        "",
        ACCEPTED.replace("Accepted", "Connection closed by"),
    ]
    r = parse_lines(lines, "linux_auth", year=2026)
    assert len(r.events) == 1
    assert r.malformed == 2
    assert r.ignored == 1
    assert [n for n, _ in r.error_samples] == [2, 3]


def test_unknown_source_rejected():
    with pytest.raises(ValueError):
        parse_lines([], "windows_evtx")


def test_to_ecs_uses_standard_field_names():
    doc = parse_ufw(UFW, 2026).to_ecs()
    assert doc["source.ip"] == "203.0.113.200"
    assert doc["destination.port"] == 22
    assert doc["event.original"] == UFW
    assert "user.name" not in doc  # None fields are dropped
