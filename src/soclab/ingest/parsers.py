"""Parsers for real Linux log formats into the common Event schema.

Each line parser returns:
  * an Event      - a security-relevant line
  * None          - a valid line we deliberately ignore (e.g. "session opened")
  * raises ValueError - a malformed line; the caller counts it and moves on
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from datetime import UTC, datetime

from soclab.schema import Event

LineParser = Callable[[str, int], Event | None]

# Syslog prefix. Ubuntu < 23.10 writes "Oct 23 14:02:11"; newer rsyslog writes RFC 3339.
_SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)"
    r"\s+(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

# Greedy (?P<user>.+) makes the regex bind to the LAST "from <ip> port <n>", which sshd
# appends itself. A username that contains a fake "from x port y" cannot spoof the IP.
_SSH_LOGIN = re.compile(
    r"^(?P<result>Accepted|Failed) (?P<method>\S+) for (?:invalid user )?(?P<user>.+)"
    r" from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?$"
)

_UFW = re.compile(r"\[UFW (?P<action>BLOCK|ALLOW|AUDIT)\]")
_KV = re.compile(r"(\w+)=(\S*)")


def parse_syslog_timestamp(ts: str, year: int) -> datetime:
    if ts[0].isdigit():
        dt = datetime.fromisoformat(ts)
        return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
    # Legacy syslog has no year or timezone; the caller supplies the year and we assume UTC.
    return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)


def _ip(value: str) -> str:
    return str(ipaddress.ip_address(value))  # raises ValueError on garbage


def _split_syslog(line: str, year: int) -> tuple[datetime, str, str, str]:
    m = _SYSLOG.match(line)
    if not m:
        raise ValueError("not a syslog line")
    return parse_syslog_timestamp(m["ts"], year), m["host"], m["proc"], m["msg"]


def parse_linux_auth(line: str, year: int) -> Event | None:
    """sshd entries from /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL)."""
    ts, host, proc, msg = _split_syslog(line, year)
    if proc != "sshd":
        return None
    m = _SSH_LOGIN.match(msg)
    if not m:
        return None  # e.g. "Connection closed", "session opened": valid but not used yet
    return Event(
        timestamp=ts,
        log_source="linux_auth",
        event_category="authentication",
        event_action="ssh_login",
        outcome="success" if m["result"] == "Accepted" else "failure",
        host_name=host,
        user_name=m["user"],
        source_ip=_ip(m["ip"]),
        source_port=int(m["port"]),
        network_transport="tcp",
        raw=line,
    )


def parse_ufw(line: str, year: int) -> Event | None:
    """Uncomplicated Firewall kernel entries, e.g. from /var/log/ufw.log."""
    ts, host, proc, msg = _split_syslog(line, year)
    action = _UFW.search(msg)
    if proc != "kernel" or not action:
        return None
    fields = dict(_KV.findall(msg))
    if "SRC" not in fields or "DST" not in fields:
        raise ValueError("UFW line without SRC/DST")
    verb = action["action"].lower()
    return Event(
        timestamp=ts,
        log_source="ufw",
        event_category="network",
        event_action=f"firewall_{verb}",
        outcome="failure" if verb == "block" else "success",
        host_name=host,
        source_ip=_ip(fields["SRC"]),
        source_port=int(fields["SPT"]) if fields.get("SPT") else None,
        destination_ip=_ip(fields["DST"]),
        destination_port=int(fields["DPT"]) if fields.get("DPT") else None,
        network_transport=fields.get("PROTO", "").lower() or None,
        raw=line,
    )


PARSERS: dict[str, LineParser] = {
    "linux_auth": parse_linux_auth,
    "ufw": parse_ufw,
}
