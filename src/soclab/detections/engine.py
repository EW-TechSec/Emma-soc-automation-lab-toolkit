"""Run Sigma rules (base and correlation) over events and produce alerts.

Flow:
  1. pySigma loads every rule file and resolves correlation references.
  2. Base rules are matched event by event (matcher.py) -> "hits".
  3. Correlations run in dependency order, so a correlation can consume the
     output of another (chaining). Their results are hits for the next level.
  4. Only rules that are not silenced by a referencing correlation produce
     alerts (Sigma's `generate` semantics, same as pySigma's output rules).
"""

from __future__ import annotations

import operator
import re
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection
from sigma.correlations import (
    SigmaCorrelationConditionOperator as Op,
)
from sigma.correlations import (
    SigmaCorrelationRule,
    SigmaCorrelationType,
)
from sigma.rule import SigmaRule

from soclab.detections.matcher import RuleMatcher, UnsupportedRuleError
from soclab.detections.models import Alert
from soclab.schema import Event

_OPS = {
    Op.LT: operator.lt,
    Op.LTE: operator.le,
    Op.GT: operator.gt,
    Op.GTE: operator.ge,
    Op.EQ: operator.eq,
    Op.NEQ: operator.ne,
}
_TECHNIQUE = re.compile(r"^t\d{4}(\.\d{3})?$")
_SUPPORTED_CORRELATIONS = {
    SigmaCorrelationType.EVENT_COUNT,
    SigmaCorrelationType.VALUE_COUNT,
    SigmaCorrelationType.TEMPORAL,
    SigmaCorrelationType.TEMPORAL_ORDERED,
}

Rule = SigmaRule | SigmaCorrelationRule


@dataclass
class _Hit:
    """One occurrence of a rule: a matching event, or an alert from a correlation."""

    time: datetime
    fields: dict[str, Any]
    events: list[Event] = field(default_factory=list)
    rule_index: int = 0  # position in a temporal correlation's rule list


def _techniques(rule: Rule) -> list[str]:
    return [
        t.name.upper() for t in rule.tags if t.namespace == "attack" and _TECHNIQUE.match(t.name)
    ]


class DetectionEngine:
    def __init__(self, collection: SigmaCollection):
        collection.resolve_rule_references()
        self.rules: list[Rule] = list(collection.rules)
        self._output_ids = {id(r) for r in collection.get_output_rules()}
        self._matchers: dict[int, RuleMatcher] = {}
        for rule in self.rules:
            if isinstance(rule, SigmaRule):
                self._matchers[id(rule)] = RuleMatcher(rule)
            elif rule.type not in _SUPPORTED_CORRELATIONS:
                raise UnsupportedRuleError(f"{rule.name}: correlation type {rule.type.name}")

    @classmethod
    def from_path(cls, rules_dir: str | Path) -> DetectionEngine:
        return cls(SigmaCollection.load_ruleset([Path(rules_dir)]))

    @property
    def alerting_rules(self) -> list[str]:
        return sorted(r.name for r in self.rules if id(r) in self._output_ids)

    # -- public API -------------------------------------------------------

    def run(self, events: Iterable[Event]) -> list[Alert]:
        events = sorted(events, key=lambda e: e.timestamp)
        hits: dict[int, list[_Hit]] = {}
        alerts: dict[int, list[Alert]] = {}

        docs = [(e, e.to_ecs()) for e in events]
        for rule in self.rules:
            if isinstance(rule, SigmaRule):
                m = self._matchers[id(rule)]
                matched = [(e, d) for e, d in docs if m.matches(e, d)]
                hits[id(rule)] = [_Hit(e.timestamp, d, [e]) for e, d in matched]
                alerts[id(rule)] = [self._alert(rule, h.time, [h], {}) for h in hits[id(rule)]]

        for rule in self._correlation_order():
            alerts[id(rule)] = self._correlate(rule, hits)
            hits[id(rule)] = [_Hit(a.timestamp, dict(a.group), a.events) for a in alerts[id(rule)]]

        out = [a for r in self.rules if id(r) in self._output_ids for a in alerts[id(r)]]
        return sorted(out, key=lambda a: a.timestamp)

    # -- correlation ------------------------------------------------------

    def _correlation_order(self) -> list[SigmaCorrelationRule]:
        """Depth-first, so referenced correlations run before the ones that use them."""
        ordered: list[SigmaCorrelationRule] = []
        seen: set[int] = set()

        def visit(rule: Rule) -> None:
            if id(rule) in seen or not isinstance(rule, SigmaCorrelationRule):
                return
            seen.add(id(rule))
            for ref in rule.rules:
                visit(ref.rule)
            ordered.append(rule)

        for rule in self.rules:
            visit(rule)
        return ordered

    def _correlate(self, rule: SigmaCorrelationRule, hits: dict[int, list[_Hit]]) -> list[Alert]:
        group_by = list(rule.group_by or [])
        groups: dict[tuple, list[_Hit]] = defaultdict(list)
        for index, ref in enumerate(rule.rules):
            for h in hits[id(ref.rule)]:
                key = tuple(h.fields.get(f) for f in group_by)
                if None in key:
                    continue  # cannot be grouped, e.g. no user.name on a firewall event
                groups[key].append(_Hit(h.time, h.fields, h.events, index))

        window = timedelta(seconds=rule.timespan.seconds)
        results: list[Alert] = []
        for key, group_hits in groups.items():
            group_hits.sort(key=lambda h: h.time)
            group = dict(zip(group_by, key, strict=True))
            if rule.type == SigmaCorrelationType.TEMPORAL_ORDERED:
                results += self._temporal_ordered(rule, group_hits, window, group)
            else:
                results += self._windowed(rule, group_hits, window, group)
        return results

    def _measure(self, rule: SigmaCorrelationRule, window: deque[_Hit]) -> int:
        if rule.type == SigmaCorrelationType.EVENT_COUNT:
            return len(window)
        if rule.type == SigmaCorrelationType.VALUE_COUNT:
            f = rule.condition.fieldref
            return len({h.fields.get(f) for h in window if h.fields.get(f) is not None})
        return len({h.rule_index for h in window})  # TEMPORAL: how many distinct rules seen

    def _windowed(self, rule, group_hits, window: timedelta, group) -> list[Alert]:
        """Sliding window. One alert per burst, extended while the condition keeps holding."""
        if rule.type == SigmaCorrelationType.TEMPORAL:
            check = lambda n: n == len(rule.rules)  # noqa: E731  every referenced rule seen
        else:
            op, count = _OPS[rule.condition.op], rule.condition.count
            check = lambda n: op(n, count)  # noqa: E731

        results: list[Alert] = []
        current: deque[_Hit] = deque()
        open_alert: Alert | None = None
        for h in group_hits:
            current.append(h)
            while h.time - current[0].time > window:
                current.popleft()
            if not check(self._measure(rule, current)):
                continue
            if open_alert and h.time - open_alert.last_seen <= window:
                open_alert.events.extend(h.events)
                open_alert.last_seen = h.time
            else:
                open_alert = self._alert(rule, h.time, list(current), group)
                results.append(open_alert)
        return results

    def _temporal_ordered(self, rule, group_hits, window: timedelta, group) -> list[Alert]:
        """Rule 1, then rule 2, ... then rule N, all inside the timespan."""
        n = len(rule.rules)
        by_index: dict[int, list[_Hit]] = defaultdict(list)
        for h in group_hits:
            by_index[h.rule_index].append(h)

        results: list[Alert] = []
        by_first_stage: dict[int, Alert] = {}
        for last in by_index[n - 1]:
            chain = [last]
            for stage in range(n - 2, -1, -1):  # walk backwards: latest earlier hit per stage
                earlier = [
                    h for h in by_index[stage]
                    if h.time <= chain[0].time and last.time - h.time <= window
                ]  # fmt: skip
                if not earlier:
                    break
                chain.insert(0, earlier[-1])
            if len(chain) != n:
                continue
            first = id(chain[0])
            if first in by_first_stage:  # same attack, another completion: extend
                alert = by_first_stage[first]
                alert.events.extend(last.events)
                alert.last_seen = last.time
            else:
                alert = self._alert(rule, last.time, chain, group)
                by_first_stage[first] = alert
                results.append(alert)
        return results

    # -- helpers ----------------------------------------------------------

    def _alert(self, rule: Rule, when: datetime, hits: list[_Hit], group) -> Alert:
        events = [e for h in hits for e in h.events]
        times = [e.timestamp for e in events] or [when]
        return Alert(
            rule_id=str(rule.id),
            rule_name=rule.name,
            title=rule.title,
            level=rule.level.name.lower() if rule.level else "informational",
            techniques=_techniques(rule),
            timestamp=when,
            first_seen=min(times),
            last_seen=max(times),
            group=dict(group),
            events=events,
        )
