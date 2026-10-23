"""Property-based tests (fuzzing): properties that must hold for ANY input, not just the
examples we thought of. Hypothesis generates the inputs and shrinks any failure to a
minimal example.
"""

import ipaddress
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from soclab.detections import DetectionEngine
from soclab.ingest import parse_lines
from soclab.ingest.parsers import parse_linux_auth
from soclab.schema import Event
from soclab.security import PathTraversalError, safe_path

RULES = Path(__file__).resolve().parents[1] / "rules"
ENGINE = DetectionEngine.from_path(RULES)
FUZZ = settings(deadline=None,
                suppress_health_check=[HealthCheck.function_scoped_fixture])  # fmt: skip

ips = st.ip_addresses(v=4).map(str)
# Usernames an attacker might send: any printable text, including fake "from x port y".
usernames = st.text(
    alphabet=st.characters(blacklist_categories=("Cc", "Cs", "Zl", "Zp")), min_size=1, max_size=60
).filter(lambda u: u.strip() == u and u != "")
injections = st.builds(
    lambda u, ip, p: f"{u} from {ip} port {p}", usernames, ips, st.integers(1, 65535)
)


# ---- parsers ---------------------------------------------------------------------


@FUZZ
@given(st.lists(st.text(max_size=300), max_size=20), st.sampled_from(["linux_auth", "ufw"]))
def test_parsers_never_crash_and_account_for_every_line(lines, source):
    lines = [x.replace("\n", " ").replace("\r", " ") for x in lines]
    r = parse_lines(lines, source, year=2026)
    non_empty = sum(1 for x in lines if x.strip())
    assert len(r.events) + r.ignored + r.malformed == non_empty


@FUZZ
@given(st.one_of(usernames, injections), ips, st.integers(1, 65535),
       st.sampled_from(["Failed", "Accepted"]))  # fmt: skip
def test_ssh_source_ip_cannot_be_spoofed_via_username(user, real_ip, port, result):
    line = (f"Oct 20 09:14:03 web01 sshd[1]: {result} password for invalid user {user} "
            f"from {real_ip} port {port} ssh2")  # fmt: skip
    event = parse_linux_auth(line, 2026)
    assert event is not None
    assert event.source_ip == str(ipaddress.ip_address(real_ip))
    assert event.source_port == port


# ---- path traversal guard -----------------------------------------------------------

path_parts = st.lists(
    st.one_of(st.sampled_from(["..", ".", "", "/", "logs", "auth.log", "..\\..", "%2e%2e"]),
              st.text(max_size=20)),
    max_size=8,
).map("/".join)  # fmt: skip


@FUZZ
@given(path_parts)
def test_safe_path_never_escapes_base(tmp_path_factory, user_input):
    base = tmp_path_factory.mktemp("base")
    try:
        result = safe_path(base, user_input)
    except PathTraversalError:
        return
    except (ValueError, OSError):
        pytest.fail(f"unexpected error type for {user_input!r}")
    assert result.is_relative_to(base.resolve())


# ---- detection engine -------------------------------------------------------------

T0 = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
events = st.builds(
    lambda sec, src, action, outcome, user, ip, port: Event(
        timestamp=T0 + timedelta(seconds=sec), log_source=src, event_category="x",
        event_action=action, outcome=outcome, host_name="web01", raw="x",
        user_name=user, source_ip=ip, destination_port=port,
    ),
    st.integers(0, 3600), st.sampled_from(["linux_auth", "ufw", "unknown"]),
    st.sampled_from(["ssh_login", "firewall_block", "other"]),
    st.sampled_from(["success", "failure", "unknown"]),
    st.one_of(st.none(), usernames), st.one_of(st.none(), ips),
    st.one_of(st.none(), st.integers(0, 65535)),
)  # fmt: skip


@FUZZ
@given(st.lists(events, max_size=80))
def test_engine_never_crashes_and_alerts_are_well_formed(evs):
    for alert in ENGINE.run(evs):
        assert alert.rule_name in ENGINE.alerting_rules
        assert alert.first_seen <= alert.last_seen
        assert alert.events, "an alert must carry evidence"
