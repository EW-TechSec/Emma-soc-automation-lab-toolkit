import ipaddress
import json
from collections import Counter

from soclab.ingest import parse_lines
from soclab.simulate import generate, write_dataset

ATTACKER_NETS = [ipaddress.ip_network("198.51.100.0/24"), ipaddress.ip_network("203.0.113.0/24")]


def _lines(pairs):
    return [line for _, line in pairs]


def test_same_seed_same_dataset():
    assert generate(seed=7).auth_lines == generate(seed=7).auth_lines


def test_different_seed_different_dataset():
    assert generate(seed=1).auth_lines != generate(seed=2).auth_lines


def test_planted_scenarios_and_safe_ip_ranges():
    gt = generate().ground_truth
    assert {g.scenario for g in gt} == {"ssh_bruteforce", "password_spray", "port_scan"}
    for g in gt:
        assert any(ipaddress.ip_address(g.source_ip) in net for net in ATTACKER_NETS)


def test_round_trip_generated_logs_parse_cleanly_and_match_ground_truth():
    ds = generate()
    auth = parse_lines(_lines(ds.auth_lines), "linux_auth", year=2026)
    ufw = parse_lines(_lines(ds.ufw_lines), "ufw", year=2026)
    assert auth.malformed == 0 and ufw.malformed == 0

    per_ip = Counter(e.source_ip for e in auth.events + ufw.events)
    for g in ds.ground_truth:
        assert per_ip[g.source_ip] == g.event_count, g.scenario


def test_benign_noise_present_for_false_positive_testing():
    ds = generate()
    auth = parse_lines(_lines(ds.auth_lines), "linux_auth", year=2026)
    staff_failures = [
        e for e in auth.events if e.outcome == "failure" and e.source_ip.startswith("10.")
    ]
    assert staff_failures, "need benign typos so detections can be tested for false positives"


def test_write_dataset(tmp_path):
    paths = write_dataset(generate(), tmp_path)
    assert paths["auth"].read_text().count("\n") > 50
    assert len(json.loads(paths["ground_truth"].read_text())) == 3
