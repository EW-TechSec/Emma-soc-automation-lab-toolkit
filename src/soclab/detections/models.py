"""What the detection engine produces."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from soclab.schema import Event


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    title: str
    level: str  # informational, low, medium, high, critical
    techniques: list[str]  # MITRE ATT&CK IDs, e.g. ["T1110.001"]
    timestamp: datetime  # when the rule's condition was first met
    first_seen: datetime
    last_seen: datetime
    group: dict[str, Any] = field(default_factory=dict)  # e.g. {"source.ip": "203.0.113.66"}
    events: list[Event] = field(default_factory=list)  # evidence

    @property
    def event_count(self) -> int:
        return len(self.events)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "title": self.title,
            "level": self.level,
            "techniques": self.techniques,
            "timestamp": self.timestamp.isoformat(),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "group": self.group,
            "event_count": self.event_count,
        }
