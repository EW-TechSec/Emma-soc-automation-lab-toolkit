"""Group alerts into incidents: one case per attacker, with a timeline and a severity.

Linking rules:
  * MERGE (strong evidence): same source.ip, and the alert starts within `max_gap` of
    the incident's last activity. IPs get reassigned, so the same IP much later may be
    a different actor.
  * RELATE (weak evidence): different incidents that touched the same host within
    `related_window` of each other are cross-referenced, never merged. Merging on weak
    evidence would hide separate attackers inside one case.

Severity: the highest alert level; multi-stage incidents (2+ ATT&CK tactics) go up one
level, capped at high; evidence of valid credentials (T1078) makes the incident critical.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from soclab.attack import VALID_ACCOUNTS, tactic_order
from soclab.detections.models import Alert

LEVELS = ["informational", "low", "medium", "high", "critical"]


@dataclass
class Incident:
    id: str
    source_ip: str
    alerts: list[Alert] = field(default_factory=list)
    related: list[str] = field(default_factory=list)  # ids of incidents sharing a host

    @property
    def first_seen(self) -> datetime:
        return min(a.first_seen for a in self.alerts)

    @property
    def last_seen(self) -> datetime:
        return max(a.last_seen for a in self.alerts)

    @property
    def tactics(self) -> list[str]:
        return sorted({t for a in self.alerts for t in a.tactics}, key=tactic_order)

    @property
    def techniques(self) -> list[str]:
        return sorted({t for a in self.alerts for t in a.techniques})

    @property
    def hosts(self) -> list[str]:
        return sorted({e.host_name for a in self.alerts for e in a.events})

    @property
    def users(self) -> list[str]:
        return sorted({e.user_name for a in self.alerts for e in a.events if e.user_name})

    @property
    def compromised(self) -> bool:
        return any(t.split(".")[0] == VALID_ACCOUNTS for t in self.techniques)

    @property
    def severity(self) -> str:
        level = max(LEVELS.index(a.level) for a in self.alerts)
        if len(self.tactics) >= 2 and level < LEVELS.index("high"):
            level += 1  # progression across the kill chain
        if self.compromised:
            level = LEVELS.index("critical")
        return LEVELS[level]

    def timeline(self) -> list[dict[str, Any]]:
        rows = []
        for a in sorted(self.alerts, key=lambda a: a.timestamp):
            hosts = sorted({e.host_name for e in a.events})
            rows.append({
                "time": a.timestamp.isoformat(),
                "rule": a.rule_name,
                "title": a.title,
                "level": a.level,
                "tactics": a.tactics,
                "techniques": a.techniques,
                "hosts": hosts,
                "user": a.group.get("user.name"),
                "events": a.event_count,
            })  # fmt: skip
        return rows

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "severity": self.severity,
            "compromised": self.compromised,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "tactics": self.tactics,
            "techniques": self.techniques,
            "hosts": self.hosts,
            "users": self.users,
            "alert_count": len(self.alerts),
            "related": self.related,
            "timeline": self.timeline(),
        }


def build_incidents(
    alerts: list[Alert],
    max_gap: timedelta = timedelta(hours=2),
    related_window: timedelta = timedelta(hours=2),
) -> list[Incident]:
    incidents: list[Incident] = []
    open_by_ip: dict[str, Incident] = {}

    for alert in sorted(alerts, key=lambda a: a.first_seen):
        ip = alert.group.get("source.ip") or "unknown"
        current = open_by_ip.get(ip)
        if current and alert.first_seen - current.last_seen <= max_gap:
            current.alerts.append(alert)
        else:
            current = Incident(id="", source_ip=ip, alerts=[alert])
            open_by_ip[ip] = current
            incidents.append(current)

    incidents.sort(key=lambda i: i.first_seen)
    for n, inc in enumerate(incidents, start=1):
        inc.id = f"INC-{inc.first_seen:%Y%m%d}-{n:04d}"

    for i, a in enumerate(incidents):
        for b in incidents[i + 1 :]:
            close = (b.first_seen - a.last_seen <= related_window
                     and a.first_seen - b.last_seen <= related_window)  # fmt: skip
            if close and set(a.hosts) & set(b.hosts):
                a.related.append(b.id)
                b.related.append(a.id)
    return incidents
