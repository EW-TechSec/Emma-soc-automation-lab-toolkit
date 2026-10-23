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
| Threat-intel enrichment (AbuseIPDB, VirusTotal, OTX), IOC handling, STIX 2.1 | `enrichment/`, `cti/` *(Phase 3)* |
| Alert triage and risk-based prioritization | `triage/` *(Phase 3)* |
| SOAR-style response playbooks with safe-by-default dry-run | `response/` *(Phase 4)* |
| ML anomaly detection with honest evaluation | `ml/` *(Phase 5)* |
| SOC dashboard and ATT&CK coverage heatmap | `dashboard/` *(Phase 6)* |
| AI-assisted triage over MCP with human-in-the-loop guardrails | `mcp_server/` *(Phase 7)* |
| CI/CD, testing, secure coding (ruff, bandit, pytest) | `.github/workflows/` |

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env        # optional: add free API keys, otherwise mocks are used
pytest

# generate a day of lab logs with planted attacks (port scan, SSH brute force, password spray)
python -m soclab.simulate --out data/generated --seed 42
```

No API keys are needed. Without them, enrichment replays recorded real API responses.
See [ADR 0001](docs/decisions/0001-live-vs-mock-threat-intel.md).

## Detections

| Rule | Type | ATT&CK | Level |
|---|---|---|---|
| [SSH brute force](rules/linux/sshd/ssh_bruteforce.yml) | event_count: 10+ failures, same source and user, 5 min | T1110.001 | high |
| [SSH password spray](rules/linux/sshd/ssh_password_spray.yml) | value_count: 10+ distinct users from one source, 30 min | T1110.003 | high |
| [Brute force then successful login](rules/linux/sshd/ssh_bruteforce_then_success.yml) | temporal_ordered: brute force, then success, 15 min | T1110.001, T1078 | critical |
| [Port scan](rules/linux/firewall/port_scan.yml) | value_count: 20+ distinct blocked ports from one source, 5 min | T1046 | medium |

Every rule is checked in CI: valid Sigma (pySigma), references resolve, metadata complete,
ATT&CK-tagged, and every field it uses exists in the event schema, so a typo cannot create
a rule that silently never fires.

## Safety

Response actions (blocking IPs, isolating hosts) run in **dry-run mode by default**.
They only log what they would do. Executing them requires an explicit `SOCLAB_DRY_RUN=false`.
All attack simulation runs against containers in a local lab, never against third-party systems.

## Roadmap

- [x] Phase 0: Project skeleton, CI, configuration
- [x] Phase 1: Common log schema, parsers, synthetic attack-data generator
- [ ] Phase 2: Detection engine, Sigma rules, ATT&CK mapping, detection tests
- [ ] Phase 3: Threat-intel enrichment and triage scoring
- [ ] Phase 4: Response playbooks and incident reports
- [ ] Phase 5: ML anomaly detection
- [ ] Phase 6: Streamlit SOC dashboard (live demo)
- [ ] Phase 7: MCP server for AI-assisted triage
- [ ] Phase 8: Case studies and demo

## License

MIT
