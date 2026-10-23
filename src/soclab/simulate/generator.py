"""Synthetic, labelled lab logs: normal activity plus planted attacks.

Output is real Linux log formats (sshd auth.log, UFW) so the same parsers work on
lab data and on real servers. Every planted attack is recorded in a ground-truth
list, which is what lets us measure detections (did we catch it? anything else?).

IP addressing (RFC 5737 documentation ranges, so no real host is ever "accused"):
  10.0.0.0/8        internal hosts and staff
  192.0.2.0/24      benign internet background noise
  198.51.100.0/24   attackers
  203.0.113.0/24    attackers
"""

from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

STAFF = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
SPRAY_USERS = STAFF + ["admin", "test", "oracle", "postgres", "ubuntu", "guest", "support"]
HOSTS = {"web01": "10.0.0.5", "bastion01": "10.0.0.10"}


@dataclass
class GroundTruth:
    scenario: str
    mitre_technique: str
    source_ip: str
    target_host: str
    start: str
    end: str
    event_count: int
    notes: str = ""
    malicious: bool = True  # False marks benign activity that is expected to look suspicious
    compromised: bool = False  # True when the attack ended with valid access (T1078)


@dataclass
class Dataset:
    auth_lines: list[tuple[datetime, str]] = field(default_factory=list)
    ufw_lines: list[tuple[datetime, str]] = field(default_factory=list)
    ground_truth: list[GroundTruth] = field(default_factory=list)


def _syslog_ts(ts: datetime) -> str:
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S}"


class _Generator:
    def __init__(self, seed: int, start: datetime):
        # Not used for security: a seeded PRNG makes datasets reproducible.
        self.rng = random.Random(seed)  # noqa: S311  # nosec B311
        self.start = start
        self.ds = Dataset()
        self._pid = 1000

    def _sshd(self, ts: datetime, host: str, msg: str) -> None:
        self._pid += self.rng.randint(1, 40)
        self.ds.auth_lines.append((ts, f"{_syslog_ts(ts)} {host} sshd[{self._pid}]: {msg}"))

    def _login(self, ts, host, user, ip, ok: bool, known_user: bool = True) -> None:
        port = self.rng.randint(32768, 60999)
        if ok:
            msg = f"Accepted password for {user} from {ip} port {port} ssh2"
        else:
            invalid = "" if known_user else "invalid user "
            msg = f"Failed password for {invalid}{user} from {ip} port {port} ssh2"
        self._sshd(ts, host, msg)
        if ok:
            self._sshd(
                ts, host, f"pam_unix(sshd:session): session opened for user {user}(uid=1001)"
            )

    def _ufw(self, ts, host, src, dport, proto="TCP", action="BLOCK") -> None:
        spt = self.rng.randint(1024, 65535)
        line = (
            f"{_syslog_ts(ts)} {host} kernel: [{self.rng.uniform(1e4, 9e5):.6f}] [UFW {action}] "
            f"IN=eth0 OUT= MAC=00:16:3e:5a:01:02:00:16:3e:00:00:01:08:00 SRC={src} "
            f"DST={HOSTS[host]} LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID={self.rng.randint(1, 65535)} "
            f"PROTO={proto} SPT={spt} DPT={dport} WINDOW=1024 RES=0x00 SYN URGP=0"
        )
        self.ds.ufw_lines.append((ts, line))

    def _at(self, minutes: float) -> datetime:
        return self.start + timedelta(minutes=minutes)

    # ---- benign activity -------------------------------------------------

    def normal_activity(self, hours: int) -> None:
        for user in STAFF:
            ip = f"10.10.0.{STAFF.index(user) + 20}"
            for day_offset in range(0, hours, 24):
                for _ in range(self.rng.randint(2, 5)):  # a few logins per working day
                    ts = self._at(day_offset * 60 + self.rng.uniform(0, 9 * 60))
                    host = self.rng.choice(list(HOSTS))
                    if self.rng.random() < 0.15:  # fat-fingered password, then success
                        for i in range(self.rng.randint(1, 2)):
                            self._login(ts + timedelta(seconds=i * 6), host, user, ip, ok=False)
                        ts += timedelta(seconds=20)
                    self._login(ts, host, user, ip, ok=True)

        # Internet background noise: single probes from many IPs. Should NOT alert.
        for _ in range(hours * 4):
            ts = self._at(self.rng.uniform(0, hours * 60))
            src = f"192.0.2.{self.rng.randint(1, 254)}"
            self._ufw(ts, self.rng.choice(list(HOSTS)), src, self.rng.choice([23, 445, 3389, 5900]))

    # ---- planted attacks -------------------------------------------------

    def ssh_bruteforce(
        self,
        at_min: float,
        ip="203.0.113.66",
        host="web01",
        user="admin",
        attempts=60,
        succeed=True,
        delay=(1, 4),
        scenario="ssh_bruteforce",
    ) -> None:
        ts = self._at(at_min)
        first = ts
        for _ in range(attempts):
            ts += timedelta(seconds=self.rng.uniform(*delay))
            self._login(ts, host, user, ip, ok=False)
        count = attempts
        if succeed:
            ts += timedelta(seconds=3)
            self._login(ts, host, user, ip, ok=True)
            count += 1
        self.ds.ground_truth.append(
            GroundTruth(
                scenario=scenario,
                mitre_technique="T1110.001",
                source_ip=ip,
                target_host=host,
                start=first.isoformat(),
                end=ts.isoformat(),
                event_count=count,
                notes="ends in a successful login (T1078 Valid Accounts)" if succeed else "",
                compromised=succeed,
            )
        )

    def password_spray(
        self, at_min: float, ip="198.51.100.77", host="bastion01", users=None, delay=(20, 60)
    ) -> None:
        users = SPRAY_USERS if users is None else users
        ts = self._at(at_min)
        first = ts
        for user in users:  # one password, many users, slow to dodge lockouts
            ts += timedelta(seconds=self.rng.uniform(*delay))
            self._login(ts, host, user, ip, ok=False, known_user=user in STAFF)
        self.ds.ground_truth.append(
            GroundTruth(
                scenario="password_spray",
                mitre_technique="T1110.003",
                source_ip=ip,
                target_host=host,
                start=first.isoformat(),
                end=ts.isoformat(),
                event_count=len(users),
            )
        )

    def port_scan(self, at_min: float, ip="203.0.113.200", host="web01", ports=120) -> None:
        ts = self._at(at_min)
        first = ts
        for dport in self.rng.sample(range(1, 10000), ports):
            ts += timedelta(milliseconds=self.rng.randint(50, 400))
            self._ufw(ts, host, ip, dport)
        self.ds.ground_truth.append(
            GroundTruth(
                scenario="port_scan",
                mitre_technique="T1046",
                source_ip=ip,
                target_host=host,
                start=first.isoformat(),
                end=ts.isoformat(),
                event_count=ports,
            )
        )

    # ---- benign but suspicious-looking --------------------------------------

    def service_account_retry(self, at_min: float, ip="10.20.0.15", host="web01") -> None:
        """A backup job with an expired password retrying. Not an attack, but it looks like one."""
        ts = self._at(at_min)
        first = ts
        attempts = self.rng.randint(12, 20)
        for _ in range(attempts):
            ts += timedelta(seconds=self.rng.uniform(10, 20))
            self._login(ts, host, "svc_backup", ip, ok=False)
        self.ds.ground_truth.append(
            GroundTruth(
                scenario="service_account_retry",
                mitre_technique="",
                source_ip=ip,
                target_host=host,
                start=first.isoformat(),
                end=ts.isoformat(),
                event_count=attempts,
                notes="benign: stale credentials in an automated job",
                malicious=False,
            )
        )

    # ---- varied scenario mix for evaluation -----------------------------------

    def varied_scenarios(self, hours: int) -> None:
        """Random attacks (size, pace, timing) plus evasions and benign look-alikes."""
        rng = self.rng
        pool = [f"203.0.113.{i}" for i in range(1, 255)] + [
            f"198.51.100.{i}" for i in range(1, 255)
        ]
        ips = iter(rng.sample(pool, 10))  # distinct attacker per scenario
        hosts = list(HOSTS)

        def when() -> float:
            return rng.uniform(0, hours * 60 - 60)

        if rng.random() < 0.8:  # size varies; small scans fall below the 20-port threshold
            self.port_scan(when(), ip=next(ips), host=rng.choice(hosts), ports=rng.randint(10, 150))
        if rng.random() < 0.9:  # pace and length vary; about half end in a successful login
            self.ssh_bruteforce(
                when(), ip=next(ips), host=rng.choice(hosts), user=rng.choice(["admin", "root"]),
                attempts=rng.randint(15, 80), succeed=rng.random() < 0.5, delay=(1, 8),
            )  # fmt: skip
        if rng.random() < 0.7:
            users = rng.sample(SPRAY_USERS, rng.randint(10, len(SPRAY_USERS)))
            self.password_spray(
                when(), ip=next(ips), host=rng.choice(hosts), users=users, delay=(20, 90)
            )
        if rng.random() < 0.3:  # evasion: one guess a minute, below any 5-minute window
            self.ssh_bruteforce(
                when(), ip=next(ips), host=rng.choice(hosts), user="root", attempts=30,
                succeed=False, delay=(50, 90), scenario="slow_bruteforce",
            )  # fmt: skip
        if rng.random() < 0.4:
            self.service_account_retry(when())


def generate(
    seed: int = 42, start: datetime | None = None, hours: int = 24, varied: bool = False
) -> Dataset:
    """Default: the fixed demo day. varied=True: a random scenario mix for evaluation."""
    start = start or datetime(2026, 10, 20, 7, 0, tzinfo=UTC)
    g = _Generator(seed, start)
    g.normal_activity(hours)
    if varied:
        g.varied_scenarios(hours)
    else:
        g.port_scan(at_min=95)  # recon first...
        g.ssh_bruteforce(at_min=140)  # ...then credential attacks
        g.password_spray(at_min=330)
    g.ds.auth_lines.sort(key=lambda x: x[0])
    g.ds.ufw_lines.sort(key=lambda x: x[0])
    return g.ds


def write_dataset(ds: Dataset, out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "auth": out / "auth.log",
        "ufw": out / "ufw.log",
        "ground_truth": out / "ground_truth.json",
    }
    paths["auth"].write_text("".join(line + "\n" for _, line in ds.auth_lines))
    paths["ufw"].write_text("".join(line + "\n" for _, line in ds.ufw_lines))
    paths["ground_truth"].write_text(json.dumps([asdict(g) for g in ds.ground_truth], indent=2))
    return paths
