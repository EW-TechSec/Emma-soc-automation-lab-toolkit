from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection

from soclab.detections import DetectionEngine, RuleMatcher, UnsupportedRuleError
from soclab.schema import Event

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
T0 = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)


def ssh(sec, outcome="failure", user="admin", ip="203.0.113.66", host="web01"):
    return Event(
        timestamp=T0 + timedelta(seconds=sec), log_source="linux_auth",
        event_category="authentication", event_action="ssh_login", outcome=outcome,
        host_name=host, raw=f"sshd {outcome} {user} {ip}", user_name=user, source_ip=ip,
    )  # fmt: skip


def block(sec, dport, ip="203.0.113.200"):
    return Event(
        timestamp=T0 + timedelta(seconds=sec), log_source="ufw", event_category="network",
        event_action="firewall_block", outcome="failure", host_name="web01", raw="ufw",
        source_ip=ip, destination_ip="10.0.0.5", destination_port=dport, network_transport="tcp",
    )  # fmt: skip


@pytest.fixture(scope="module")
def engine():
    return DetectionEngine.from_path(RULES_DIR)


def names(alerts):
    return sorted(a.rule_name for a in alerts)


# ---- which rules alert (Sigma `generate` semantics) -------------------------


def test_alerting_rules_match_pysigma(engine):
    expected = ["port_scan", "ssh_bruteforce", "ssh_bruteforce_then_success", "ssh_password_spray"]
    assert engine.alerting_rules == expected
    c = SigmaCollection.load_ruleset([RULES_DIR])
    c.resolve_rule_references()
    assert sorted(r.name for r in c.get_output_rules()) == expected


def test_building_blocks_never_alert_alone(engine):
    # Two staff typos and a login: base rules match, but nothing should alert.
    events = [ssh(0, user="alice", ip="10.10.0.20"), ssh(5, user="alice", ip="10.10.0.20"),
              ssh(20, "success", user="alice", ip="10.10.0.20")]  # fmt: skip
    assert engine.run(events) == []


# ---- event_count: brute force ---------------------------------------------


def test_bruteforce_below_threshold_is_silent(engine):
    assert engine.run([ssh(i * 3) for i in range(9)]) == []


def test_bruteforce_at_threshold_alerts_once(engine):
    alerts = engine.run([ssh(i * 3) for i in range(10)])
    assert names(alerts) == ["ssh_bruteforce"]
    assert alerts[0].timestamp == T0 + timedelta(seconds=27)  # the 10th failure
    assert alerts[0].group == {"source.ip": "203.0.113.66", "user.name": "admin"}


def test_long_bruteforce_is_one_alert_with_all_evidence(engine):
    alerts = engine.run([ssh(i * 3) for i in range(60)])
    assert len(alerts) == 1 and alerts[0].event_count == 60


def test_two_bursts_far_apart_are_two_alerts(engine):
    first = [ssh(i * 3) for i in range(10)]
    second = [ssh(3600 + i * 3) for i in range(10)]
    assert names(engine.run(first + second)) == ["ssh_bruteforce", "ssh_bruteforce"]


def test_slow_guessing_outside_window_is_silent(engine):
    # One try per minute: never 10 inside 5 minutes. (A known evasion, see journal.)
    assert engine.run([ssh(i * 60) for i in range(30)]) == []


def test_bruteforce_counts_per_source_and_user(engine):
    # 5 failures each from two IPs: neither reaches 10.
    events = [ssh(i, ip="203.0.113.1") for i in range(5)] + [
        ssh(i, ip="203.0.113.2") for i in range(5)
    ]
    assert engine.run(events) == []


# ---- value_count: password spray and port scan ------------------------------


def test_spray_needs_distinct_users(engine):
    spray = [ssh(i * 30, user=f"user{i}", ip="198.51.100.77") for i in range(10)]
    assert names(engine.run(spray)) == ["ssh_password_spray"]


def test_one_user_many_tries_is_not_a_spray(engine):
    assert "ssh_password_spray" not in names(engine.run([ssh(i * 3) for i in range(30)]))


def test_port_scan_distinct_ports(engine):
    assert names(engine.run([block(i, 1000 + i) for i in range(20)])) == ["port_scan"]
    assert engine.run([block(i, 22) for i in range(50)]) == []  # same port 50 times: not a scan


# ---- temporal_ordered: brute force then success -----------------------------


def test_bruteforce_then_success_is_critical(engine):
    alerts = engine.run([ssh(i * 3) for i in range(12)] + [ssh(40, "success")])
    chain = [a for a in alerts if a.rule_name == "ssh_bruteforce_then_success"]
    assert len(chain) == 1
    assert chain[0].level == "critical"
    assert chain[0].techniques == ["T1110.001", "T1078"]
    assert chain[0].event_count == 13


def test_success_before_bruteforce_is_not_a_chain(engine):
    events = [ssh(0, "success")] + [ssh(10 + i * 3) for i in range(12)]
    assert names(engine.run(events)) == ["ssh_bruteforce"]


def test_success_for_other_user_is_not_a_chain(engine):
    events = [ssh(i * 3) for i in range(12)] + [ssh(40, "success", user="alice")]
    assert names(engine.run(events)) == ["ssh_bruteforce"]


def test_success_too_late_is_not_a_chain(engine):
    events = [ssh(i * 3) for i in range(12)] + [ssh(3600, "success")]
    assert names(engine.run(events)) == ["ssh_bruteforce"]


def test_stage_rule_mirrors_alerting_rule(engine):
    by_name = {r.name: r for r in engine.rules}
    a, b = by_name["ssh_bruteforce"], by_name["ssh_bruteforce_stage"]
    assert (a.type, a.group_by, a.timespan.seconds, a.condition.op, a.condition.count) == (
        b.type, b.group_by, b.timespan.seconds, b.condition.op, b.condition.count
    )  # fmt: skip
    assert [r.rule.name for r in a.rules] == [r.rule.name for r in b.rules]


# ---- matcher: Sigma value semantics -----------------------------------------


def _matcher(detection: str) -> RuleMatcher:
    y = f"title: t\nname: t\nlogsource: {{product: linux, service: sshd}}\ndetection:\n{detection}"
    return RuleMatcher(SigmaCollection.from_yaml(y).rules[0])


@pytest.mark.parametrize(
    ("detection", "expected"),
    [
        ("  sel: {user.name: ADMIN}\n  condition: sel", True),  # case-insensitive by default
        ("  sel: {user.name|cased: ADMIN}\n  condition: sel", False),
        ("  sel: {user.name|startswith: adm}\n  condition: sel", True),
        ("  sel: {user.name: adm}\n  condition: sel", False),  # fields match whole value
        ("  sel: {user.name: [root, admin]}\n  condition: sel", True),  # list means OR
        ("  sel: {source.ip|cidr: 203.0.113.0/24}\n  condition: sel", True),
        ("  sel: {source.ip|cidr: 10.0.0.0/8}\n  condition: sel", False),
        ("  sel: {source.port|gte: 1024}\n  condition: sel", True),
        ("  sel: {user.name|re: '^ad.in$'}\n  condition: sel", True),
        ("  sel: {destination.port|exists: false}\n  condition: sel", True),
        (
            "  sel: {user.name: admin}\n  flt: {source.ip|cidr: 203.0.113.0/24}\n"
            "  condition: sel and not flt",
            False,
        ),  # fmt: skip
        ("  kw: [failure]\n  condition: kw", True),  # keyword searches the raw line
        ("  sel: {destination.ip: null}\n  condition: sel", True),  # field absent
    ],
)
def test_matcher_semantics(detection, expected):
    event = Event(
        timestamp=T0, log_source="linux_auth", event_category="authentication",
        event_action="ssh_login", outcome="failure", host_name="web01",
        raw="sshd failure admin", user_name="admin", source_ip="203.0.113.66", source_port=51122,
    )  # fmt: skip
    assert _matcher(detection).matches(event) is expected


def test_logsource_must_match():
    assert not _matcher("  sel: {source.ip|cidr: 0.0.0.0/0}\n  condition: sel").matches(
        block(0, 22)
    )


def test_unsupported_feature_fails_loudly():
    with pytest.raises(UnsupportedRuleError, match="SigmaFieldReference"):
        _matcher("  sel: {user.name|fieldref: host.name}\n  condition: sel")
