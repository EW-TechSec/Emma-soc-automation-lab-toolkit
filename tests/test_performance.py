"""Denial-of-service regressions. Log content and traffic volume are attacker-controlled:
a slow regex or a quadratic algorithm lets an attacker stall detection.

Limits are generous (roughly 10x the measured time) so slow CI runners do not flake,
while a return to the old quadratic behaviour (about 38 s for 40,000 events) still fails.
"""

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from soclab.detections import DetectionEngine
from soclab.ingest.parsers import parse_linux_auth, parse_ufw
from soclab.schema import Event

RULES = Path(__file__).resolve().parents[1] / "rules"
T0 = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
P = "Oct 20 09:14:03 web01 sshd[1]: "


def _elapsed(fn) -> float:
    start = time.perf_counter()
    fn()
    return time.perf_counter() - start


@pytest.mark.parametrize(
    ("parser", "line"),
    [
        (parse_linux_auth, P + "Failed password for " + " from 1.2.3.4" * 70_000),
        (parse_linux_auth, P + "Failed password for " + " from 1.2.3.4 port" * 50_000),
        (parse_linux_auth, "Oct 20 09:14:03 " + "a " * 500_000),
        (parse_ufw, "Oct 20 09:14:03 web01 kernel: [UFW BLOCK] " + "A=" * 500_000),
    ],
    ids=["many-from", "many-from-port", "space-flood", "ufw-kv-flood"],
)
def test_no_redos_on_megabyte_lines(parser, line):
    def parse():
        try:
            parser(line, 2026)
        except ValueError:
            pass

    assert len(line) >= 900_000
    assert _elapsed(parse) < 1.0


def _scan(n: int) -> list[Event]:
    return [
        Event(T0 + timedelta(milliseconds=6 * i), "ufw", "network", "firewall_block", "failure",
              "web01", "x", source_ip="203.0.113.200", destination_ip="10.0.0.5",
              destination_port=1 + i % 65535)
        for i in range(n)
    ]  # fmt: skip


def test_fast_scan_flood_is_linear():
    engine = DetectionEngine.from_path(RULES)
    events = _scan(40_000)  # ~4 minutes of a fast scanner, one window
    alerts = []
    assert _elapsed(lambda: alerts.extend(engine.run(events))) < 5.0
    assert [a.rule_name for a in alerts] == ["port_scan"]  # still one deduplicated alert
