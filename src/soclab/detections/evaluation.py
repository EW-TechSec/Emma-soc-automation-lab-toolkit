"""Measure detection quality against simulator ground truth.

Matching is deliberately strict. An alert is a TRUE alert only if:
  1. its rule is one that is meant to catch the scenario (SCENARIO_RULES),
  2. its source.ip is the scenario's source IP, and
  3. its evidence overlaps the scenario's time window.
Anything else is a FALSE alert. Per rule:
  precision = true alerts / all alerts             ("when it fires, is it real?")
  recall    = attacks detected / attacks expected  ("of the real attacks, how many caught?")
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from statistics import median

from soclab.detections.engine import DetectionEngine
from soclab.detections.models import Alert
from soclab.ingest import parse_lines
from soclab.simulate import GroundTruth, generate

# Which rules SHOULD fire for each malicious scenario.
SCENARIO_RULES: dict[str, set[str]] = {
    "port_scan": {"port_scan"},
    "ssh_bruteforce": {"ssh_bruteforce"},
    "slow_bruteforce": {"ssh_bruteforce"},  # known evasion, expected to be missed
    "password_spray": {"ssh_password_spray"},
}
COMPROMISE_RULE = "ssh_bruteforce_then_success"


def expected_rules(gt: GroundTruth) -> set[str]:
    if not gt.malicious:
        return set()
    rules = set(SCENARIO_RULES.get(gt.scenario, set()))
    if gt.compromised:
        rules.add(COMPROMISE_RULE)
    return rules


@dataclass
class RuleScore:
    rule: str
    alerts: int = 0
    true_alerts: int = 0
    attacks: int = 0  # scenarios this rule is expected to catch
    detected: int = 0
    detect_seconds: list[float] = field(default_factory=list)  # attack start -> alert
    false_positive_causes: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    @property
    def false_alerts(self) -> int:
        return self.alerts - self.true_alerts

    @property
    def precision(self) -> float | None:
        return self.true_alerts / self.alerts if self.alerts else None

    @property
    def recall(self) -> float | None:
        return self.detected / self.attacks if self.attacks else None

    @property
    def median_time_to_detect(self) -> float | None:
        return median(self.detect_seconds) if self.detect_seconds else None

    def add(self, other: RuleScore) -> None:
        self.alerts += other.alerts
        self.true_alerts += other.true_alerts
        self.attacks += other.attacks
        self.detected += other.detected
        self.detect_seconds += other.detect_seconds
        for cause, n in other.false_positive_causes.items():
            self.false_positive_causes[cause] += n


def _overlaps(alert: Alert, gt: GroundTruth) -> bool:
    start, end = datetime.fromisoformat(gt.start), datetime.fromisoformat(gt.end)
    return alert.first_seen <= end and alert.last_seen >= start


def score(alerts: list[Alert], truth: list[GroundTruth], rules: list[str]) -> dict[str, RuleScore]:
    scores = {r: RuleScore(r) for r in rules}
    for gt in truth:
        for r in expected_rules(gt) & set(rules):
            scores[r].attacks += 1

    detected: set[tuple[int, str]] = set()  # (ground truth index, rule)
    for alert in alerts:
        s = scores.setdefault(alert.rule_name, RuleScore(alert.rule_name))
        s.alerts += 1
        ip = alert.group.get("source.ip")
        matches = [
            i for i, gt in enumerate(truth)
            if alert.rule_name in expected_rules(gt) and gt.source_ip == ip and _overlaps(alert, gt)
        ]  # fmt: skip
        if not matches:
            # Explain the false positive if it lines up with known benign activity.
            cause = next(
                (gt.scenario for gt in truth if gt.source_ip == ip and _overlaps(alert, gt)),
                "unexplained",
            )
            s.false_positive_causes[cause] += 1
            continue
        s.true_alerts += 1
        for i in matches:
            if (i, alert.rule_name) not in detected:
                detected.add((i, alert.rule_name))
                s.detected += 1
                start = datetime.fromisoformat(truth[i].start)
                s.detect_seconds.append((alert.timestamp - start).total_seconds())
    return scores


@dataclass
class SuiteResult:
    seeds: list[int]
    rules: dict[str, RuleScore]
    scenarios: dict[str, list[int]]  # scenario -> [count, detected by all expected rules]


def run_suite(seeds: list[int], rules_dir: str | Path = "rules", hours: int = 24) -> SuiteResult:
    engine = DetectionEngine.from_path(rules_dir)
    totals = {r: RuleScore(r) for r in engine.alerting_rules}
    scenarios: dict[str, list[int]] = defaultdict(lambda: [0, 0])

    for seed in seeds:
        ds = generate(seed=seed, hours=hours, varied=True)
        year = ds.ground_truth[0].start[:4] if ds.ground_truth else None
        events = parse_lines([x for _, x in ds.auth_lines], "linux_auth", int(year or 2026)).events
        events += parse_lines([x for _, x in ds.ufw_lines], "ufw", int(year or 2026)).events
        alerts = engine.run(events)
        for name, s in score(alerts, ds.ground_truth, engine.alerting_rules).items():
            totals.setdefault(name, RuleScore(name)).add(s)
        for gt in ds.ground_truth:
            label = gt.scenario + (" (compromised)" if gt.compromised else "")
            want = expected_rules(gt)
            hit = all(
                any(a.rule_name == r and a.group.get("source.ip") == gt.source_ip
                    and _overlaps(a, gt) for a in alerts)
                for r in want
            )  # fmt: skip
            scenarios[label][0] += 1
            # Benign scenarios count as "handled" when nothing alerted on them.
            fired = any(
                a.group.get("source.ip") == gt.source_ip and _overlaps(a, gt) for a in alerts
            )
            scenarios[label][1] += int(hit if want else not fired)
    return SuiteResult(list(seeds), totals, dict(scenarios))


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.2f}"


def to_markdown(result: SuiteResult) -> str:
    n = len(result.seeds)
    lines = [
        "# Detection Quality",
        "",
        f"Measured over **{n} simulated days** (seeds {result.seeds[0]} to {result.seeds[-1]}) of",
        "varied attacks, evasions and benign look-alikes. Generated by",
        f"`python -m soclab.detections.evaluation --seeds {n}`.",
        "",
        "## Per rule",
        "",
        "| Rule | Alerts | True | False | Attacks | Detected | Precision | Recall "
        "| Median time to detect |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name in sorted(result.rules):
        s = result.rules[name]
        ttd = s.median_time_to_detect
        ttd_txt = "n/a" if ttd is None else f"{ttd:.0f} s"
        lines.append(
            f"| `{name}` | {s.alerts} | {s.true_alerts} | {s.false_alerts} | {s.attacks} | "
            f"{s.detected} | {_pct(s.precision)} | {_pct(s.recall)} | {ttd_txt} |"
        )
    lines += ["", "## Per scenario", "", "| Scenario | Occurrences | Handled correctly |",
              "|---|---|---|"]  # fmt: skip
    for label in sorted(result.scenarios):
        count, ok = result.scenarios[label]
        lines.append(f"| {label} | {count} | {ok} ({ok / count:.0%}) |")
    causes = {
        f"`{name}`: {cause}": c
        for name, s in result.rules.items()
        for cause, c in s.false_positive_causes.items()
    }
    lines += ["", "## False positive causes", ""]
    lines += [f"- {k}: {v}" for k, v in sorted(causes.items())] or ["- none"]
    lines += [
        "",
        "Benign scenarios are handled correctly when nothing alerts on them; malicious ones",
        "when every rule meant to catch them fires.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Score detections against simulated ground truth.")
    ap.add_argument("--seeds", type=int, default=50, help="number of simulated days")
    ap.add_argument("--rules", default="rules")
    ap.add_argument("--out", help="write the markdown report to this file")
    args = ap.parse_args()
    report = to_markdown(run_suite(list(range(args.seeds)), args.rules))
    print(report)
    if args.out:
        Path(args.out).write_text(report)


if __name__ == "__main__":
    main()
