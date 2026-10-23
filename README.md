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
| Detection engineering (Sigma rules, MITRE ATT&CK mapping, detection-as-code tests) | `detections/` *(Phase 2)* |
| Log parsing and normalization | `ingest/` *(Phase 1)* |
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
```

No API keys are needed. Without them, enrichment replays recorded real API responses.
See [ADR 0001](docs/decisions/0001-live-vs-mock-threat-intel.md).

## Safety

Response actions (blocking IPs, isolating hosts) run in **dry-run mode by default**.
They only log what they would do. Executing them requires an explicit `SOCLAB_DRY_RUN=false`.
All attack simulation runs against containers in a local lab, never against third-party systems.

## Roadmap

- [x] Phase 0: Project skeleton, CI, configuration
- [ ] Phase 1: Common log schema, parsers, synthetic attack-data generator
- [ ] Phase 2: Detection engine, Sigma rules, ATT&CK mapping, detection tests
- [ ] Phase 3: Threat-intel enrichment and triage scoring
- [ ] Phase 4: Response playbooks and incident reports
- [ ] Phase 5: ML anomaly detection
- [ ] Phase 6: Streamlit SOC dashboard (live demo)
- [ ] Phase 7: MCP server for AI-assisted triage
- [ ] Phase 8: Case studies and demo

## License

MIT
