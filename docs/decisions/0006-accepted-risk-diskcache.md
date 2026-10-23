# ADR 0006: Accepted risk, diskcache PYSEC-2026-2447 (transitive dependency)

**Status:** Accepted. **Review:** when diskcache publishes a fix, when pySigma changes how it
uses diskcache, or by 2027-04-23, whichever comes first.

## Context

`pip-audit` reports PYSEC-2026-2447 in `diskcache` 5.6.3: it serialises cache entries with
Python `pickle`, so anyone with write access to the cache directory can achieve arbitrary
code execution when the cache is read. No fixed version exists.

We do not use diskcache directly. It is a dependency of pySigma, which uses it only in
`sigma.data.mitre_attack` and `sigma.data.mitre_d3fend` to cache downloaded MITRE data
(default directory `~/.cache/pysigma`).

## Analysis

- **Reachability:** none of our workloads (simulation, ingestion, detection engine, incidents,
  evaluation, KQL conversion) import `diskcache` or `sigma.data`. Checked in a fresh
  interpreter; pySigma's cache directory is never created.
- **Exploit precondition:** the attacker must already be able to write to the user's cache
  directory, i.e. already has local access as that user.

## Decision

- Accept the risk. CI runs `pip-audit --ignore-vuln PYSEC-2026-2447`: only this ID is ignored,
  any other vulnerability still fails the build.
- `tests/test_supply_chain.py` runs the workloads in a fresh interpreter and fails if
  `diskcache` or `sigma.data` is ever loaded, which would make the vulnerability reachable
  and void this decision.

## Consequences

- The build stays green without hiding new vulnerabilities.
- If MITRE data lookups from pySigma are ever needed, this decision must be revisited first
  (for example pointing the cache at a directory only the service account can write).
