# ADR 0004: Group alerts into incidents by attacker, relate by shared host

**Status:** Accepted

## Context

Analysts work cases, not single alerts. On the demo day a brute force alert and a
"brute force then successful login" alert describe one attack, and should be one case
with one timeline and one severity. Other alerts are possibly connected but not proven
to be: a port scan and a brute force against the same host from different IPs.

## Decision

- **Merge (strong evidence):** alerts with the same `source.ip` join one incident if they
  start within 2 hours of the incident's last activity. The gap is measured from the latest
  activity, so a long-running attack stays one incident, but an IP seen again much later
  (possibly reassigned: cloud, mobile, NAT) starts a new one.
- **Relate (weak evidence):** incidents from different IPs that touched the same host within
  2 hours of each other are cross-referenced in `related`, never merged.
- **Severity:** the highest alert level; two or more ATT&CK tactics raise it one level, capped
  at high; any alert with T1078 (valid accounts) makes the incident critical.
- **IDs:** `INC-<date of first activity>-<sequence>`, ordered by first activity, so the same
  input always gives the same IDs.

## Consequences

- Over-merging, which hides separate attackers inside one case, is avoided on purpose;
  the analyst still sees possible links through `related`.
- An attacker who changes IP between stages produces separate, related incidents, not one.
  Linking by other entities (user, file hash, infrastructure) is future work.
- In the varied simulation every attack uses its own IP, so grouping is modest
  (1.16 alerts per incident over 50 days); it grows with multi-stage attacks from one source.
