# Emma SOC Automation Lab Toolkit

![CI](https://github.com/EW-TechSec/Emma-soc-automation-lab-toolkit/actions/workflows/ci.yml/badge.svg)

A hands-on Security Operations lab in Python. It takes raw logs through the same stages a
SOC uses for an alert, from detection through to an incident report:

```
 Logs ──► INGEST ──► DETECT ──► ENRICH ──► TRIAGE ──► RESPOND ──► REPORT
          normalize   Sigma +    AbuseIPDB  risk       block /     incident
          to one      ATT&CK,    VirusTotal score,     isolate /   report,
          schema      ML         OTX        priority   notify      dashboard
                                   ▲
            MCP server: an AI analyst can call each stage as a tool
```

## What this project demonstrates

| Skill | Where |
|---|---|
| Detection engineering: Sigma v2 rules incl. correlations, MITRE ATT&CK mapping, CI-validated with pySigma | [`rules/`](rules/) |
| Log parsing and normalization to Elastic Common Schema, log-injection-resistant parsing | `ingest/`, `schema.py` |
| Labelled attack simulation (T1046, T1110.001, T1110.003) with benign noise | `simulate/` |
| Alert grouping into incidents with ATT&CK timeline and severity escalation | `detections/incidents.py` |
| Microsoft Sentinel KQL from the same rules: custom pySigma backend, ECS to ASIM mapping | [`kql/`](kql/), `kql.py` |
| Threat-intel enrichment (AbuseIPDB, VirusTotal, OTX), IOC handling, STIX 2.1 | `enrichment/`, `cti/` *(Phase 3)* |
| Alert triage and risk-based prioritization | `triage/` *(Phase 3)* |
| SOAR-style response playbooks with safe-by-default dry-run | `response/` *(Phase 4)* |
| ML anomaly detection with honest evaluation | `ml/` *(Phase 5)* |
| SOC dashboard and ATT&CK coverage heatmap | `dashboard/` *(Phase 6)* |
| AI-assisted triage over MCP with human-in-the-loop guardrails | `mcp_server/` *(Phase 7)* |
| CI/CD and secure development: tests, fuzzing, type checks, SAST, dependency CVE audit, SHA-pinned actions | `.github/workflows/`, `tests/` |

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest

# generate a day of lab logs with planted attacks (port scan, SSH brute force, password spray)
python -m soclab.simulate --out data/generated --seed 42

# run every Sigma rule over those logs
python -m soclab.detections --logs data/generated --year 2026

# same, grouped into incidents with a timeline
python -m soclab.detections --logs data/generated --year 2026 --incidents

# score the rules against ground truth over 50 varied simulated days
python -m soclab.detections.evaluation --seeds 50

# convert the rules to KQL for Microsoft Sentinel (ASIM)
python -m soclab.kql
```

Everything above runs offline with no accounts or API keys. Threat-intel enrichment
(Phase 3) will use free AbuseIPDB, VirusTotal and OTX keys when present and recorded real
responses otherwise ([ADR 0001](docs/decisions/0001-live-vs-mock-threat-intel.md)).

## Detections

| Rule | Type | ATT&CK | Level |
|---|---|---|---|
| [SSH brute force](rules/linux/sshd/ssh_bruteforce.yml) | event_count: 10+ failures, same source and user, 5 min | T1110.001 | high |
| [SSH password spray](rules/linux/sshd/ssh_password_spray.yml) | value_count: 10+ distinct users from one source, 30 min | T1110.003 | high |
| [Brute force then successful login](rules/linux/sshd/ssh_bruteforce_then_success.yml) | temporal_ordered: brute force, then success, 15 min | T1110.001, T1078 | critical |
| [Port scan](rules/linux/firewall/port_scan.yml) | value_count: 20+ distinct blocked ports from one source, 5 min | T1046 | medium |

Rules run in a small engine built on pySigma's parser
([ADR 0003](docs/decisions/0003-detection-engine-on-pysigma.md)): sliding-window correlations,
one alert per attack burst, and Sigma's `generate` semantics. On the generated lab day it raises
4 alerts covering all 3 planted attacks, with no alerts from staff typos or internet noise.

### Same rules, Microsoft Sentinel

The Sigma rules are converted to KQL against Sentinel's ASIM normalized schema with a custom
pySigma backend and field mapping ([ADR 0005](docs/decisions/0005-kql-backend-for-sentinel.md)).
Generated queries live in [`kql/`](kql/), and CI fails if they drift from the rules:

```kusto
imAuthentication
| where EventType =~ "Logon" and EventResult =~ "Failure" and not(TargetUsername =~ "svc_backup" and ipv4_is_in_range(SrcIpAddr, "10.20.0.0/24"))
| summarize EventCount = count() by bin(TimeGenerated, 5m), SrcIpAddr, TargetUsername
| where EventCount >= 10
```

Known difference: KQL `bin()` uses fixed windows while the Python engine slides, so a burst
straddling a window edge can be missed in KQL; a test pins this case. The queries are tested
as text and not yet executed against a live workspace.

### From alerts to incidents

Alerts from the same attacker are grouped into one incident with a timeline, ATT&CK tactics
and a severity ([ADR 0004](docs/decisions/0004-incident-grouping.md)). On the demo day:

```
4 alerts -> 3 incidents

INC-20261020-0002  CRITICAL  attacker 203.0.113.66  COMPROMISED
    hosts=['web01'] users=['admin'] tactics=['initial_access', 'credential_access']
    09:20:24  ssh_bruteforce               credential_access  (60 events)
    09:22:23  ssh_bruteforce_then_success  credential_access, initial_access  (61 events)
    related: INC-20261020-0001 (same host, close in time)
```

The port scan on the same host from a different IP is linked as related, not merged:
merging on weak evidence would hide separate attackers in one case.

### Measured detection quality

Scored against ground truth over 50 simulated days of varied attacks, evasions and benign
look-alikes ([full report](docs/detection-quality.md)):

| Rule | Precision | Recall | Median time to detect |
|---|---|---|---|
| Port scan | 1.00 | 0.88 | 4 s |
| SSH brute force | 1.00 | 0.75 | 44 s |
| Brute force then successful login | 1.00 | 1.00 | 251 s |
| Password spray | 1.00 | 1.00 | 558 s |

The gaps are known and tested rather than hidden: scans under 20 ports and low-and-slow
brute force (one guess a minute) are missed. Brute force precision started at 0.61 because
of a backup job retrying an expired password; a scoped exclusion fixed it with no loss of
detections. Precision only covers the benign activity the lab simulates.

Every rule is checked in CI: valid Sigma (pySigma), references resolve, metadata complete,
ATT&CK-tagged, and every field it uses exists in the event schema, so a typo cannot create
a rule that silently never fires. Every alerting rule also ships with a true positive and a
boundary-case true negative log in [`tests/fixtures/detections/`](tests/fixtures/detections/),
and CI fails if measured precision or recall regresses.

## Quality and security checks

Every push runs these gates in CI (Python 3.11 and 3.12):

| Gate | What it catches |
|---|---|
| `pip check` | Dependency conflicts, e.g. a package silently downgrading pySigma |
| ruff, mypy | Lint errors and type bugs |
| bandit | Insecure code patterns |
| pip-audit | Known vulnerabilities in dependencies ([one accepted, unreachable finding](docs/decisions/0006-accepted-risk-diskcache.md), guarded by a test) |
| pytest, 98% coverage | Unit, rule, detection-quality, CLI and regression tests |
| Hypothesis fuzzing | Parsers never crash, a crafted username cannot spoof the source IP, `safe_path()` never escapes its base |
| Performance tests | No regex denial of service on megabyte log lines; the engine stays linear under a 40,000-packet scan flood |

## Safety

- **Dry-run by default:** the configuration already enforces it (and a test guards it), so the
  response playbooks planned for Phase 4 (blocking IPs, isolating hosts) will only log what
  they would do unless `SOCLAB_DRY_RUN=false` is set explicitly.
- **No real targets:** attacks are simulated as log files, and attacker addresses come only from
  IP ranges reserved for documentation (RFC 5737). The live attack lab planned for Phase 8 runs
  only between local containers on an isolated network.
- **Untrusted input:** log content is treated as attacker-controlled: injection-resistant
  parsing, path traversal guard, and fuzz and denial-of-service tests.

## Roadmap

- [x] Phase 0: Project skeleton, CI, configuration
- [x] Phase 1: Common log schema, parsers, synthetic attack-data generator
- [x] Phase 2: Sigma rules with correlations and ATT&CK mapping, detection engine, measured
      detection quality and tuning, incident grouping, KQL for Microsoft Sentinel
- [x] Quality and security pass: fuzzing, ReDoS and load tests, type checking, dependency
      audit, six bugs found and fixed
- [ ] Phase 3: Threat-intel enrichment and triage scoring
- [ ] Phase 4: Response playbooks and incident reports
- [ ] Phase 5: ML anomaly detection
- [ ] Phase 6: Streamlit SOC dashboard (live demo)
- [ ] Phase 7: MCP server for AI-assisted triage
- [ ] Phase 8: Live Docker attack lab, public dataset replay, case studies and demo

## License

MIT
