# ADR 0005: Own KQL backend and ASIM pipeline for Microsoft Sentinel

**Status:** Accepted

## Context

The same detections should be deployable on Microsoft Sentinel and Defender XDR, which use
KQL. pySigma converts rules through a backend (target language) and a processing pipeline
(field and value mapping).

Installing the official `pysigma-backend-kusto` (1.0.1, the latest) silently downgraded
pySigma from 2.0.1 to 1.5.1: every version of that backend requires `pysigma<2.0.0`, and the
detection engine is built on pySigma 2.0. That backend also has no correlation support, and
every alerting rule here is a correlation.

## Decision

- **Backend:** `soclab.kql.KqlBackend`, a subclass of pySigma 2.0's `TextQueryBackend`, the same
  extension point the official backends use. Case-insensitive `=~` and `in~` (Sigma strings are
  case-insensitive; `==` and `in` would silently become case-sensitive), `ipv4_is_in_range` for
  CIDR, and `not(...)` always wrapped (in KQL `not` is a function).
- **Correlations:** `event_count` and `value_count` use pySigma's templates
  (`summarize count()` / `dcount()` by `bin(TimeGenerated, <timespan>)` and the group-by
  fields). `temporal_ordered` is written by hand (earliest first stage <= latest last stage,
  via `minif` and `maxif`), because the templates cannot express per-stage timestamps.
- **Schema:** a processing pipeline maps our ECS names and values to ASIM
  (`source.ip` to `SrcIpAddr`, `failure` to `Failure`, `firewall_block` to `DvcAction == Deny`)
  and selects the ASIM parser: `imAuthentication` for sshd, `imNetworkSession` for firewall.
- **Delivery:** `python -m soclab.kql` writes one file per alerting rule to `kql/`. A test
  regenerates them and fails if the committed files are stale.
- **Dependencies:** CI runs `pip check`, so a silent downgrade fails the build. pySigma moved
  from the dev extras to runtime dependencies (the engine imports it at runtime; a plain
  `pip install .` would have failed).

## Consequences

- **Tumbling vs sliding windows:** `bin()` creates fixed windows; the Python engine slides.
  A burst that straddles a bin boundary can be split and missed in KQL (pinned by a test:
  12 failures in 2 minutes across 09:05 alert in the engine, but no bin reaches 10). On the
  50-day simulation all 44 fast brute forces are caught either way, because they are well
  above the threshold. Near-threshold attacks carry the risk; a sliding alternative is
  `row_window_session()` or a self-join, at higher query cost.
- **`dcount()` is approximate** (HyperLogLog). At these counts the error is negligible.
- **Not yet executed against a live workspace.** The queries are generated, reviewed and tested
  as text. Running them on real data (for example an Azure Data Explorer free cluster with
  ingested lab logs) is the next validation step. UFW logs also need a custom ASIM parser to
  appear in `imNetworkSession`.
