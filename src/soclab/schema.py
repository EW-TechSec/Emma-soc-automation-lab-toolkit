"""Common event schema.

Every parser converts its log format into Event so detections are written once and
work across sources. Field names follow the Elastic Common Schema (ECS), so an SSH
failure and a firewall block both expose the attacker as `source.ip`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

Outcome = Literal["success", "failure", "unknown"]


@dataclass(frozen=True, slots=True)
class Event:
    timestamp: datetime  # always timezone-aware UTC
    log_source: str  # e.g. "linux_auth", "ufw"
    event_category: str  # ECS event.category: "authentication", "network"
    event_action: str  # e.g. "ssh_login", "firewall_block"
    outcome: Outcome
    host_name: str
    raw: str  # original line, kept for analysts and for evidence
    user_name: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    network_transport: str | None = None  # "tcp" / "udp"

    def to_ecs(self) -> dict[str, Any]:
        """Flat ECS-style dict (dotted keys), ready for JSON, pandas or a SIEM."""
        doc = {
            "@timestamp": self.timestamp.isoformat(),
            "event.module": self.log_source,
            "event.category": self.event_category,
            "event.action": self.event_action,
            "event.outcome": self.outcome,
            "host.name": self.host_name,
            "user.name": self.user_name,
            "source.ip": self.source_ip,
            "source.port": self.source_port,
            "destination.ip": self.destination_ip,
            "destination.port": self.destination_port,
            "network.transport": self.network_transport,
            "event.original": self.raw,
        }
        return {k: v for k, v in doc.items() if v is not None}
