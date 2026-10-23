# ADR 0001: Live threat-intel APIs with recorded-response fallback

**Status:** Accepted

## Context

Enrichment uses AbuseIPDB, VirusTotal and AlienVault OTX. All three have free tiers,
but with rate limits (VirusTotal: 4 requests/min). Anyone cloning this repo, and the CI
pipeline, may have no API keys. Keys must never be committed.

## Decision

Each provider sits behind one interface with two backends:

- **live**: used when a key is present in `.env` and `SOCLAB_OFFLINE` is not set
- **mock**: replays real API responses recorded once and stored as JSON fixtures

`soclab.config.Settings.intel_mode()` makes the choice in one place. CI always sets
`SOCLAB_OFFLINE=1`.

## Consequences

- The project runs end to end with zero setup, and tests are deterministic.
- Fixtures can drift from the live API format over time and need to be re-recorded occasionally.
- Live lookups are cached locally to stay within free-tier limits.
