from datetime import UTC, datetime, timedelta

import pytest

from soclab.detections.evaluation import expected_rules, run_suite, score, to_markdown
from soclab.detections.models import Alert
from soclab.simulate import GroundTruth, generate

T0 = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
RULES = ["port_scan", "ssh_bruteforce", "ssh_bruteforce_then_success", "ssh_password_spray"]


def gt(scenario="ssh_bruteforce", ip="203.0.113.66", start=0, end=120, **kw):
    return GroundTruth(
        scenario=scenario, mitre_technique="T1110.001", source_ip=ip, target_host="web01",
        start=(T0 + timedelta(seconds=start)).isoformat(),
        end=(T0 + timedelta(seconds=end)).isoformat(), event_count=10, **kw,
    )  # fmt: skip


def alert(rule="ssh_bruteforce", ip="203.0.113.66", first=30, last=90):
    return Alert(
        rule_id="x", rule_name=rule, title="t", level="high", techniques=[],
        timestamp=T0 + timedelta(seconds=first), first_seen=T0 + timedelta(seconds=first),
        last_seen=T0 + timedelta(seconds=last), group={"source.ip": ip},
    )  # fmt: skip


# ---- scoring rules ---------------------------------------------------------


def test_expected_rules():
    assert expected_rules(gt()) == {"ssh_bruteforce"}
    assert expected_rules(gt(compromised=True)) == {"ssh_bruteforce", "ssh_bruteforce_then_success"}
    assert expected_rules(gt("service_account_retry", malicious=False)) == set()


def test_true_alert_detected_with_time_to_detect():
    s = score([alert()], [gt()], RULES)["ssh_bruteforce"]
    assert (s.alerts, s.true_alerts, s.attacks, s.detected) == (1, 1, 1, 1)
    assert s.precision == 1.0 and s.recall == 1.0
    assert s.detect_seconds == [30.0]


def test_wrong_ip_is_false_positive_and_attack_missed():
    s = score([alert(ip="203.0.113.99")], [gt()], RULES)["ssh_bruteforce"]
    assert (s.false_alerts, s.detected) == (1, 0)
    assert s.precision == 0.0 and s.recall == 0.0
    assert dict(s.false_positive_causes) == {"unexplained": 1}


def test_alert_outside_attack_window_is_false_positive():
    s = score([alert(first=500, last=600)], [gt()], RULES)["ssh_bruteforce"]
    assert s.false_alerts == 1 and s.detected == 0


def test_wrong_rule_for_scenario_is_false_positive():
    # A port scan alert on the brute force IP is not credit for the port scan rule.
    s = score([alert(rule="port_scan")], [gt()], RULES)["port_scan"]
    assert s.false_alerts == 1


def test_alert_on_benign_lookalike_is_explained():
    truth = [gt("service_account_retry", ip="10.20.0.15", malicious=False)]
    s = score([alert(ip="10.20.0.15")], truth, RULES)["ssh_bruteforce"]
    assert dict(s.false_positive_causes) == {"service_account_retry": 1}


def test_duplicate_alerts_count_one_detection():
    s = score([alert(first=30, last=60), alert(first=70, last=100)], [gt()], RULES)[
        "ssh_bruteforce"
    ]
    assert (s.alerts, s.true_alerts, s.detected) == (2, 2, 1)


def test_no_alerts_means_precision_undefined_not_zero():
    s = score([], [gt()], RULES)["ssh_bruteforce"]
    assert s.precision is None and s.recall == 0.0


# ---- the simulator's varied mode ------------------------------------------


def test_default_dataset_unchanged_by_varied_mode():
    assert [g.scenario for g in generate().ground_truth] == [
        "port_scan", "ssh_bruteforce", "password_spray",
    ]  # fmt: skip


def test_varied_mode_mixes_scenarios():
    seen = {g.scenario for s in range(30) for g in generate(seed=s, varied=True).ground_truth}
    assert seen == {
        "port_scan", "ssh_bruteforce", "password_spray", "slow_bruteforce", "service_account_retry",
    }  # fmt: skip


# ---- quality gate: measured results must not regress ------------------------


@pytest.fixture(scope="module")
def suite():
    return run_suite(list(range(20)))


def test_quality_gate(suite):
    r = suite.rules
    # Precision: no rule may raise false alarms on the simulated benign activity.
    for name, s in r.items():
        assert s.precision == 1.0, f"{name} precision {s.precision}"
    # Recall: these rules catch every attack they are meant for.
    for name in ("ssh_password_spray", "ssh_bruteforce_then_success"):
        assert r[name].recall == 1.0, name
    # Known, documented gaps: small port scans and low-and-slow brute force.
    assert r["port_scan"].recall >= 0.8
    assert r["ssh_bruteforce"].recall >= 0.7


def test_known_evasion_is_measured_not_hidden(suite):
    count, handled = suite.scenarios["slow_bruteforce"]
    assert count > 0 and handled == 0  # if this starts passing, update the docs: gap closed


def test_report_renders(suite):
    md = to_markdown(suite)
    assert "| `ssh_bruteforce` |" in md and "## Per scenario" in md
