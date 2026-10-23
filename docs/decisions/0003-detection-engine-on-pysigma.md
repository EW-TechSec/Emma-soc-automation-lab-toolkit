# ADR 0003: Own detection engine on top of the pySigma parser

**Status:** Accepted

## Context

The Sigma rules need to run against our events locally, in tests and in CI, without a SIEM.
pySigma is the official Sigma library. It parses and validates rules and converts them into
SIEM queries (KQL, SPL, ...), but it does not evaluate rules against events itself.

## Decision

- **Parsing:** pySigma. It handles YAML, value modifiers (`|startswith`, `|cidr`, ...),
  condition expressions and correlation references, exactly as the specification defines.
- **Evaluation:** our own engine (`soclab/detections/`). The matcher walks pySigma's parsed
  condition tree; the correlation engine implements `event_count`, `value_count`,
  `temporal` and `temporal_ordered` with sliding time windows grouped by `group-by` fields.
- **Which rules alert:** the specification's `generate` semantics, taken from pySigma
  (`get_output_rules()`). A rule referenced by a correlation is silenced unless that
  correlation sets `generate: true`. A test asserts our engine and pySigma agree.
- **Fail loudly:** any condition node, value type or correlation type the engine does not
  support raises `UnsupportedRuleError` when rules load. A rule is never half-evaluated.

## Consequences

- The engine is small enough to explain line by line, and rule semantics stay standard.
- Correlation alerts are deduplicated: one alert per burst, extended with evidence while the
  condition keeps holding, instead of one alert per event above the threshold.
- **Found while building:** `ssh_bruteforce_then_success` referenced `ssh_bruteforce`, which
  silenced the stand-alone brute force alert, so a failed brute force raised nothing. Fixed
  with a building block, `ssh_bruteforce_stage`, used only by the chain. A test keeps its
  logic identical to `ssh_bruteforce`, and another pins the set of alerting rules.
- Unsupported today: `value_sum`, `value_avg`, `value_percentile`, `value_median`,
  `|fieldref`, and multiple conditions per rule. Adding one means extending the engine and
  its tests; until then, rules using them fail to load with a clear message.
