"""Evaluate a parsed Sigma base rule against one event.

pySigma parses the YAML, applies value modifiers (|startswith becomes a wildcard,
lists become OR, "1 of sel*" is expanded) and hands us a condition tree. This
module walks that tree. Anything it does not understand raises
UnsupportedRuleError at load time: a rule must never be half-evaluated and
silently match nothing.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
)

from soclab.schema import Event

# Our log sources expressed as Sigma logsource attributes.
LOGSOURCES: dict[str, dict[str, str]] = {
    "linux_auth": {"product": "linux", "service": "sshd"},
    "ufw": {"product": "linux", "category": "firewall"},
}

_RE_FLAGS = {
    SigmaRegularExpressionFlag.IGNORECASE: re.IGNORECASE,
    SigmaRegularExpressionFlag.MULTILINE: re.MULTILINE,
    SigmaRegularExpressionFlag.DOTALL: re.DOTALL,
}
_COMPARE = {
    SigmaCompareExpression.CompareOperators.LT: lambda a, b: a < b,
    SigmaCompareExpression.CompareOperators.LTE: lambda a, b: a <= b,
    SigmaCompareExpression.CompareOperators.GT: lambda a, b: a > b,
    SigmaCompareExpression.CompareOperators.GTE: lambda a, b: a >= b,
    SigmaCompareExpression.CompareOperators.NEQ: lambda a, b: a != b,
}
_SUPPORTED_VALUES = (
    SigmaString,
    SigmaNumber,
    SigmaCIDRExpression,
    SigmaRegularExpression,
    SigmaCompareExpression,
    SigmaNull,
    SigmaBool,
    SigmaExists,
)


class UnsupportedRuleError(ValueError):
    """The rule uses a Sigma feature this engine cannot evaluate."""


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class RuleMatcher:
    def __init__(self, rule: SigmaRule):
        self.rule = rule
        conditions = rule.detection.parsed_condition
        if len(conditions) != 1:
            raise UnsupportedRuleError(f"{rule.name}: exactly one condition is supported")
        self.tree = conditions[0].parse()
        self._regex: dict[int, re.Pattern[str]] = {}
        self._validate(self.tree)

    # -- load-time checks -------------------------------------------------

    def _nodes(self, node) -> Iterator[Any]:
        yield node
        for child in getattr(node, "args", None) or []:
            yield from self._nodes(child)

    def _validate(self, tree) -> None:
        known = (ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression,
                 ConditionValueExpression)  # fmt: skip
        for node in self._nodes(tree):
            if not isinstance(node, known):
                raise UnsupportedRuleError(
                    f"{self.rule.name}: unsupported node {type(node).__name__}"
                )
            value = getattr(node, "value", None)
            if value is not None and not isinstance(value, _SUPPORTED_VALUES):
                raise UnsupportedRuleError(
                    f"{self.rule.name}: unsupported value type {type(value).__name__}"
                )

    # -- evaluation -------------------------------------------------------

    def applies_to(self, event: Event) -> bool:
        """Rule logsource must agree with the event's source on every attribute it sets."""
        ours = LOGSOURCES.get(event.log_source, {})
        ls = self.rule.logsource
        wanted = {"product": ls.product, "category": ls.category, "service": ls.service}
        return all(ours.get(k) == v for k, v in wanted.items() if v)

    def matches(self, event: Event, doc: dict[str, Any] | None = None) -> bool:
        if not self.applies_to(event):
            return False
        return self._eval(self.tree, doc if doc is not None else event.to_ecs())

    def _eval(self, node, doc: dict[str, Any]) -> bool:
        if isinstance(node, ConditionAND):
            return all(self._eval(a, doc) for a in node.args)
        if isinstance(node, ConditionOR):
            return any(self._eval(a, doc) for a in node.args)
        if isinstance(node, ConditionNOT):
            return not self._eval(node.args[0], doc)
        if isinstance(node, ConditionFieldEqualsValueExpression):
            return self._match_value(node.value, doc.get(node.field), node.field in doc)
        # Keyword (no field): search the original log line.
        return self._match_value(node.value, doc.get("event.original"), True, search=True)

    def _pattern(self, value) -> re.Pattern[str]:
        key = id(value)
        if key not in self._regex:
            if isinstance(value, SigmaRegularExpression):
                flags = 0
                for f in value.flags:
                    flags |= _RE_FLAGS[f]
                self._regex[key] = re.compile(str(value.regexp), flags)
            else:
                # Sigma strings are case-insensitive unless the |cased modifier is used.
                flags = 0 if isinstance(value, SigmaCasedString) else re.IGNORECASE
                self._regex[key] = re.compile(str(value.to_regex().regexp), flags | re.DOTALL)
        return self._regex[key]

    def _match_value(self, value, actual: Any, present: bool, search: bool = False) -> bool:
        if isinstance(value, SigmaExists):
            return present == value.exists
        if isinstance(value, SigmaNull):
            return actual is None
        if actual is None:
            return False
        if isinstance(value, SigmaBool):
            return actual is value.boolean
        if isinstance(value, SigmaNumber):
            return _number(actual) == value.number
        if isinstance(value, SigmaCompareExpression):
            n = _number(actual)
            return n is not None and _COMPARE[value.op](n, value.number.number)
        if isinstance(value, SigmaCIDRExpression):
            try:
                return ipaddress.ip_address(str(actual)) in value.network
            except ValueError:
                return False
        if isinstance(value, SigmaRegularExpression):
            return self._pattern(value).search(str(actual)) is not None
        # SigmaString: a field must match the whole value; a keyword may appear anywhere.
        pattern = self._pattern(value)
        text = str(actual)
        return bool(pattern.search(text) if search else pattern.fullmatch(text))
