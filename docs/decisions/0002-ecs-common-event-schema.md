# ADR 0002: Normalize all logs to an ECS-based event schema

**Status:** Accepted

## Context

Each log source writes the same facts differently. sshd writes `from 203.0.113.66 port 51122`,
and UFW writes `SRC=203.0.113.200 SPT=40000`. If detections parse raw text, every rule has to
be rewritten for every source, and an IP seen by the firewall cannot be linked to the same IP
seen by sshd.

## Decision

Parsers convert every line into one `Event` (`soclab/schema.py`) whose field names follow the
[Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html): `source.ip`,
`user.name`, `event.outcome`, `destination.port`, and so on. The original line is kept in
`event.original` as evidence.

Parsers never crash on bad input. Malformed lines are counted and sampled; valid but
irrelevant lines are counted as ignored.

## Consequences

- Detections (Phase 2) are written once against ECS fields and work on any source.
- Output can be shipped to Elastic, or mapped to Microsoft Sentinel's ASIM, with little change.
- Adding a source means writing one parser function and registering it in `PARSERS`.
- Legacy syslog timestamps have no year or timezone. The caller supplies the year and UTC is
  assumed. Logs spanning New Year need the year split per file.
