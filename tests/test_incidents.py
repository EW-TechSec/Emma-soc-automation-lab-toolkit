from datetime import UTC, datetime, timedelta

from soclab.detections import DetectionEngine
from soclab.detections.incidents import build_incidents
from soclab.detections.models import Alert
from soclab.ingest import load_log
from soclab.schema import Event
from soclab.simulate import generate, write_dataset

T0 = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)


def alert(rule, ip, minute, level="high", tactics=("credential_access",), techniques=("T1110.001",),
          host="web01", user="admin"):  # fmt: skip
    t = T0 + timedelta(minutes=minute)
    ev = Event(timestamp=t, log_source="linux_auth", event_category="authentication",
               event_action="ssh_login", outcome="failure", host_name=host, raw="x",
               user_name=user, source_ip=ip)  # fmt: skip
    return Alert(rule_id="x", rule_name=rule, title=rule, level=level,
                 techniques=list(techniques), timestamp=t, first_seen=t, last_seen=t,
                 group={"source.ip": ip}, events=[ev], tactics=list(tactics))  # fmt: skip


# ---- merging -----------------------------------------------------------------


def test_same_ip_close_in_time_is_one_incident():
    incs = build_incidents([alert("a", "203.0.113.66", 0), alert("b", "203.0.113.66", 90)])
    assert len(incs) == 1 and len(incs[0].alerts) == 2


def test_same_ip_after_long_gap_is_a_new_incident():
    # IPs get reassigned: the same address hours later may be someone else.
    incs = build_incidents([alert("a", "203.0.113.66", 0), alert("b", "203.0.113.66", 121)])
    assert len(incs) == 2


def test_gap_is_measured_from_last_activity():
    # Each alert is within 2 h of the previous one, so the chain stays one incident.
    alerts = [alert("a", "203.0.113.66", m) for m in (0, 100, 200, 300)]
    assert len(build_incidents(alerts)) == 1


def test_different_ips_never_merge():
    incs = build_incidents([alert("a", "203.0.113.66", 0), alert("b", "203.0.113.67", 1)])
    assert len(incs) == 2


# ---- related (weak link) -----------------------------------------------------


def test_same_host_close_in_time_is_related_not_merged():
    scan = alert("port_scan", "203.0.113.200", 0, level="medium", tactics=("discovery",))
    brute = alert("ssh_bruteforce", "203.0.113.66", 45)
    a, b = build_incidents([scan, brute])
    assert a.related == [b.id] and b.related == [a.id]


def test_different_hosts_are_not_related():
    incs = build_incidents([alert("a", "203.0.113.1", 0, host="web01"),
                            alert("b", "203.0.113.2", 5, host="bastion01")])  # fmt: skip
    assert all(i.related == [] for i in incs)


def test_same_host_far_apart_is_not_related():
    incs = build_incidents([alert("a", "203.0.113.1", 0), alert("b", "203.0.113.2", 300)])
    assert all(i.related == [] for i in incs)


# ---- severity ------------------------------------------------------------------


def test_severity_is_highest_alert_level():
    inc = build_incidents([alert("a", "203.0.113.1", 0, level="medium")])[0]
    assert inc.severity == "medium" and not inc.compromised


def test_multi_stage_escalates_one_level():
    alerts = [alert("scan", "203.0.113.1", 0, level="medium", tactics=("discovery",)),
              alert("brute", "203.0.113.1", 10, level="medium")]  # fmt: skip
    assert build_incidents(alerts)[0].severity == "high"


def test_multi_stage_escalation_is_capped_at_high():
    alerts = [alert("scan", "203.0.113.1", 0, level="medium", tactics=("discovery",)),
              alert("brute", "203.0.113.1", 10, level="high")]  # fmt: skip
    assert build_incidents(alerts)[0].severity == "high"


def test_valid_accounts_means_critical():
    alerts = [alert("brute", "203.0.113.1", 0, level="medium"),
              alert("chain", "203.0.113.1", 2, level="medium",
                    tactics=("credential_access", "initial_access"),
                    techniques=("T1110.001", "T1078"))]  # fmt: skip
    inc = build_incidents(alerts)[0]
    assert inc.compromised and inc.severity == "critical"


# ---- ids, ordering, output -------------------------------------------------------


def test_ids_are_ordered_by_first_seen():
    incs = build_incidents([alert("b", "203.0.113.2", 30), alert("a", "203.0.113.1", 0)])
    assert [i.id for i in incs] == ["INC-20261020-0001", "INC-20261020-0002"]
    assert incs[0].source_ip == "203.0.113.1"


def test_tactics_follow_kill_chain_and_timeline_follows_time():
    alerts = [alert("chain", "203.0.113.1", 5, tactics=("credential_access", "initial_access")),
              alert("scan", "203.0.113.1", 0, tactics=("discovery",))]  # fmt: skip
    inc = build_incidents(alerts)[0]
    assert inc.tactics == ["initial_access", "credential_access", "discovery"]
    assert [r["rule"] for r in inc.timeline()] == ["scan", "chain"]
    d = inc.to_dict()
    assert d["alert_count"] == 2 and d["timeline"][0]["rule"] == "scan"


# ---- end to end on the demo day ----------------------------------------------------


def test_demo_day_incidents(tmp_path):
    write_dataset(generate(), tmp_path)
    events = (load_log(tmp_path, "auth.log", "linux_auth", 2026).events
              + load_log(tmp_path, "ufw.log", "ufw", 2026).events)  # fmt: skip
    alerts = DetectionEngine.from_path("rules").run(events)
    scan, brute, spray = build_incidents(alerts)
    assert len(alerts) == 4
    assert [len(i.alerts) for i in (scan, brute, spray)] == [1, 2, 1]
    assert brute.compromised and brute.severity == "critical" and brute.users == ["admin"]
    assert scan.related == [brute.id] and spray.related == []
