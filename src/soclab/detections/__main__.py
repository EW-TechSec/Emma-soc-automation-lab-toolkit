"""CLI: python -m soclab.detections --logs data/generated [--incidents] [--json out.json]"""

import argparse
import json
from pathlib import Path

from soclab.detections.engine import DetectionEngine
from soclab.detections.incidents import build_incidents
from soclab.ingest import load_log

LOG_FILES = {"auth.log": "linux_auth", "ufw.log": "ufw"}


def main() -> None:
    ap = argparse.ArgumentParser(description="Run Sigma detections over lab logs.")
    ap.add_argument("--logs", default="data/generated", help="directory with auth.log / ufw.log")
    ap.add_argument("--rules", default="rules", help="directory with Sigma rules")
    ap.add_argument("--year", type=int, default=None, help="year for legacy syslog timestamps")
    ap.add_argument("--incidents", action="store_true", help="group alerts into incidents")
    ap.add_argument("--json", help="also write alerts (or incidents) to this JSON file")
    args = ap.parse_args()

    events = []
    for name, source in LOG_FILES.items():
        if (Path(args.logs) / name).exists():
            result = load_log(args.logs, name, source, args.year)
            events += result.events
            print(f"{name}: {len(result.events)} events, {result.malformed} malformed")

    engine = DetectionEngine.from_path(args.rules)
    alerts = engine.run(events)
    print(f"\n{len(alerts)} alerts from rules {engine.alerting_rules}\n")
    for a in alerts:
        who = ", ".join(f"{k}={v}" for k, v in a.group.items())
        print(f"{a.timestamp:%Y-%m-%d %H:%M:%S}  {a.level.upper():<8}  {a.rule_name:<28} "
              f"{', '.join(a.techniques):<20} {who}  ({a.event_count} events)")  # fmt: skip

    output = [a.to_dict() for a in alerts]
    if args.incidents:
        incidents = build_incidents(alerts)
        print(f"\n{len(alerts)} alerts -> {len(incidents)} incidents\n")
        for inc in incidents:
            print(f"{inc.id}  {inc.severity.upper():<8}  attacker {inc.source_ip}"
                  f"{'  COMPROMISED' if inc.compromised else ''}")  # fmt: skip
            print(f"    hosts={inc.hosts} users={inc.users[:5]} tactics={inc.tactics}")
            for row in inc.timeline():
                print(f"    {row['time'][11:19]}  {row['rule']:<28} {', '.join(row['tactics'])}"
                      f"  ({row['events']} events)")  # fmt: skip
            if inc.related:
                print(f"    related: {', '.join(inc.related)} (same host, close in time)")
        output = [i.to_dict() for i in incidents]

    if args.json:
        Path(args.json).write_text(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
