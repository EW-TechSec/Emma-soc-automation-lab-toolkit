from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection

from soclab.detections import DetectionEngine
from soclab.kql import KqlBackend, asim_pipeline, convert_rules, write_kql
from soclab.schema import Event

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
KQL = convert_rules(RULES)
ECS_NAMES = ("event.action", "event.outcome", "user.name", "source.ip", "destination.port")


def _convert(detection: str, logsource="{product: linux, service: sshd}") -> str:
    y = f"title: t\nname: t\nlogsource: {logsource}\ndetection:\n{detection}"
    return KqlBackend(processing_pipeline=asim_pipeline()).convert(SigmaCollection.from_yaml(y))[0]


# ---- the deployable set ---------------------------------------------------


def test_every_alerting_rule_converts():
    assert sorted(KQL) == DetectionEngine.from_path(RULES).alerting_rules


def test_committed_kql_is_in_sync_with_rules(tmp_path):
    # Generated files that silently go stale are a classic detection-as-code bug.
    for path in write_kql(RULES, tmp_path):
        committed = ROOT / "kql" / path.name
        assert committed.exists(), f"missing {committed}: run python -m soclab.kql"
        assert committed.read_text() == path.read_text(), f"{committed} is stale"
    assert {p.name for p in (ROOT / "kql").glob("*.kql")} == {f"{n}.kql" for n in KQL}


@pytest.mark.parametrize("name", sorted(KQL))
def test_asim_names_only(name):
    q = KQL[name]
    assert not any(f in q for f in ECS_NAMES), "ECS field name leaked into KQL"
    assert "UNMAPPED_LOGSOURCE" not in q
    assert q.count("| where") >= 1


def test_tables_per_logsource():
    assert KQL["ssh_bruteforce"].startswith("imAuthentication\n")
    assert KQL["port_scan"].startswith("imNetworkSession\n")


def test_value_mapping_and_exclusion_survive():
    q = KQL["ssh_bruteforce"]
    assert 'EventType =~ "Logon"' in q and 'EventResult =~ "Failure"' in q
    assert (
        'not(TargetUsername =~ "svc_backup" and ipv4_is_in_range(SrcIpAddr, "10.20.0.0/24"))' in q
    )


def test_correlations():
    assert "count() by bin(TimeGenerated, 5m), SrcIpAddr, TargetUsername" in KQL["ssh_bruteforce"]
    assert "| where EventCount >= 10" in KQL["ssh_bruteforce"]
    assert (
        "dcount(TargetUsername) by bin(TimeGenerated, 30m), SrcIpAddr" in KQL["ssh_password_spray"]
    )
    assert "dcount(DstPortNumber)" in KQL["port_scan"]


def test_temporal_ordered_checks_order():
    q = KQL["ssh_bruteforce_then_success"]
    assert q.startswith("union\n")
    assert 'T0 = minif(TimeGenerated, EventRule == "ssh_bruteforce_stage")' in q
    assert 'T1 = maxif(TimeGenerated, EventRule == "ssh_successful_login")' in q
    assert q.rstrip().endswith("| where T0 <= T1")


# ---- KQL language traps -------------------------------------------------------


@pytest.mark.parametrize(
    ("detection", "expected"),
    [
        ("  sel: {user.name: ADMIN}\n  condition: sel", 'TargetUsername =~ "ADMIN"'),
        ("  sel: {user.name|cased: ADMIN}\n  condition: sel", 'TargetUsername == "ADMIN"'),
        ("  sel: {user.name: [root, admin]}\n  condition: sel", 'TargetUsername in~ ("root", "admin")'),  # noqa: E501  one row per case reads best
        ("  sel: {user.name|startswith: adm}\n  condition: sel", 'TargetUsername startswith "adm"'),
        ("  sel: {source.ip|cidr: 10.0.0.0/8}\n  condition: sel", 'ipv4_is_in_range(SrcIpAddr, "10.0.0.0/8")'),  # noqa: E501  one row per case reads best
        ("  sel: {user.name|re: '^ad.in$'}\n  condition: sel", 'TargetUsername matches regex "^ad.in$"'),  # noqa: E501  one row per case reads best
        ("  sel: {user.name: admin}\n  condition: not sel", 'not(TargetUsername =~ "admin")'),
        ("  sel: {user.name: 'a\"b'}\n  condition: sel", 'TargetUsername =~ "a\\"b"'),
    ],
)  # fmt: skip
def test_kql_syntax(detection, expected):
    assert expected in _convert(detection)


# ---- documented difference: tumbling vs sliding windows ------------------------


def test_tumbling_bins_can_split_a_burst_the_engine_catches():
    """12 failures in 2 minutes across a 5-minute boundary: 6 before 09:05, 6 after.

    The Python engine (sliding window) sees 12 in 5 minutes and alerts. KQL's
    bin(TimeGenerated, 5m) puts 6 in each bin, below 10, so the Sentinel query would
    miss it. Documented in ADR 0005.
    """
    start = datetime(2026, 10, 20, 9, 4, tzinfo=UTC)
    times = [start + timedelta(seconds=10 * i) for i in range(12)]  # 09:04:00 to 09:05:50
    events = [
        Event(timestamp=t, log_source="linux_auth", event_category="authentication",
              event_action="ssh_login", outcome="failure", host_name="web01", raw="x",
              user_name="admin", source_ip="203.0.113.66")
        for t in times
    ]  # fmt: skip
    sliding = [a.rule_name for a in DetectionEngine.from_path(RULES).run(events)]
    tumbling = Counter(t.replace(minute=t.minute - t.minute % 5, second=0) for t in times)
    assert "ssh_bruteforce" in sliding
    assert max(tumbling.values()) < 10  # KQL bin() view of the same events: no alert


def test_kql_handles_rule_without_name_or_source_file(tmp_path):
    # Regression: unnamed rules and rules without a source path must not crash conversion.
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "unnamed.yml").write_text(
        "title: Unnamed\nid: 22222222-2222-4222-8222-222222222222\n"
        "logsource: {product: linux, service: sshd}\n"
        "detection:\n  sel: {event.outcome: failure}\n  condition: sel\nlevel: low\n"
    )
    written = write_kql(rules, tmp_path / "kql")
    assert [p.name for p in written] == ["22222222-2222-4222-8222-222222222222.kql"]
    assert 'EventResult =~ "Failure"' in written[0].read_text()


@pytest.mark.parametrize("ctype", ["temporal", "value_sum"])
def test_kql_refuses_unsupported_correlations(ctype):
    y = (
        "title: F\nname: f\nlogsource: {product: linux, service: sshd}\n"
        "detection:\n  sel: {event.outcome: failure}\n  condition: sel\n---\n"
        f"title: C\nname: c\ncorrelation:\n  type: {ctype}\n  rules: [f]\n"
        "  group-by: [source.ip]\n  timespan: 5m\n  condition: {field: source.port, gte: 1}\n"
    )
    with pytest.raises(NotImplementedError):
        KqlBackend(processing_pipeline=asim_pipeline()).convert(SigmaCollection.from_yaml(y))
