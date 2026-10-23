"""Smoke tests: every command-line tool runs end to end, and fails loudly on bad input."""

import json
import sys
from pathlib import Path

import pytest

from soclab import kql
from soclab.detections import __main__ as detections_cli
from soclab.detections import evaluation
from soclab.simulate import __main__ as simulate_cli

RULES = str(Path(__file__).resolve().parents[1] / "rules")


def run(monkeypatch, main, *args):
    monkeypatch.setattr(sys, "argv", ["prog", *args])
    main()


@pytest.fixture
def lab(tmp_path, monkeypatch):
    run(monkeypatch, simulate_cli.main, "--out", str(tmp_path / "logs"), "--seed", "42")
    return tmp_path


def test_simulate_writes_logs_and_ground_truth(lab, capsys):
    logs = lab / "logs"
    assert {p.name for p in logs.iterdir()} == {"auth.log", "ufw.log", "ground_truth.json"}
    assert len(json.loads((logs / "ground_truth.json").read_text())) == 3


def test_detections_cli_alerts_and_incidents(lab, monkeypatch, capsys):
    out = lab / "incidents.json"
    run(monkeypatch, detections_cli.main, "--logs", str(lab / "logs"), "--rules", RULES,
        "--year", "2026", "--incidents", "--json", str(out))  # fmt: skip
    text = capsys.readouterr().out
    assert "4 alerts -> 3 incidents" in text
    assert "COMPROMISED" in text
    incidents = json.loads(out.read_text())
    assert [i["severity"] for i in incidents] == ["medium", "critical", "high"]


def test_detections_cli_refuses_missing_logs(tmp_path, monkeypatch, capsys):
    # A typo must not look like "0 alerts, all clear".
    with pytest.raises(SystemExit) as exc:
        run(monkeypatch, detections_cli.main, "--logs", str(tmp_path / "typo"), "--rules", RULES)
    assert exc.value.code == 2
    assert "no log files" in capsys.readouterr().err


@pytest.mark.parametrize("rules", ["missing", "empty"])
def test_detections_cli_refuses_missing_or_empty_rules(lab, monkeypatch, capsys, rules):
    rules_dir = lab / rules
    if rules == "empty":
        rules_dir.mkdir()
    with pytest.raises(SystemExit) as exc:
        run(monkeypatch, detections_cli.main, "--logs", str(lab / "logs"),
            "--rules", str(rules_dir))  # fmt: skip
    assert exc.value.code == 2
    assert "rules" in capsys.readouterr().err.lower()


def test_evaluation_cli_writes_report(tmp_path, monkeypatch, capsys):
    report = tmp_path / "quality.md"
    run(monkeypatch, evaluation.main, "--seeds", "3", "--rules", RULES, "--out", str(report))
    assert report.read_text().startswith("# Detection Quality")
    assert "| `ssh_bruteforce` |" in capsys.readouterr().out


def test_kql_cli_writes_one_file_per_alerting_rule(tmp_path, monkeypatch):
    run(monkeypatch, kql.main, "--rules", RULES, "--out", str(tmp_path))
    assert len(list(tmp_path.glob("*.kql"))) == 4
