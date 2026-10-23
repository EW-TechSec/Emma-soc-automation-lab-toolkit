"""Rule quality gate: every Sigma rule is valid, complete, ATT&CK-mapped and uses real fields."""

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaDetection, SigmaRule

from soclab.schema import Event

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
TECHNIQUE = re.compile(r"^t\d{4}(\.\d{3})?$")


def _collection() -> SigmaCollection:
    c = SigmaCollection.load_ruleset([RULES_DIR], collect_errors=True)
    c.resolve_rule_references()  # raises if a correlation names a rule that does not exist
    return c


RULES = _collection().rules


def _ecs_fields() -> set[str]:
    full = Event(
        timestamp=datetime.now(UTC), log_source="x", event_category="x", event_action="x",
        outcome="success", host_name="x", raw="x", user_name="x", source_ip="1.1.1.1",
        source_port=1, destination_ip="1.1.1.1", destination_port=1, network_transport="tcp",
    )  # fmt: skip
    return set(full.to_ecs())


def _fields_used(rule) -> set[str]:
    if isinstance(rule, SigmaCorrelationRule):
        used = set(rule.group_by or [])
        if rule.condition.fieldref:
            used.add(rule.condition.fieldref)
        return used

    def walk(items):
        for item in items:
            if isinstance(item, SigmaDetection):
                yield from walk(item.detection_items)
            elif item.field:
                yield item.field

    return {f for d in rule.detection.detections.values() for f in walk(d.detection_items)}


def test_rules_exist_and_parse_without_errors():
    assert len(RULES) >= 7
    for r in RULES:
        assert not r.errors, f"{r.name}: {r.errors}"


def test_ids_and_names_unique():
    assert len({r.id for r in RULES}) == len(RULES)
    assert len({r.name for r in RULES}) == len(RULES)


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.name)
def test_required_metadata(rule):
    for attr in ("title", "id", "name", "description", "author", "date", "level", "status"):
        assert getattr(rule, attr), f"{rule.name} is missing {attr}"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.name)
def test_mapped_to_attack_technique(rule):
    techniques = [t.name for t in rule.tags if t.namespace == "attack" and TECHNIQUE.match(t.name)]
    assert techniques, f"{rule.name} has no MITRE ATT&CK technique tag"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.name)
def test_only_uses_fields_that_exist_in_schema(rule):
    unknown = _fields_used(rule) - _ecs_fields()
    assert not unknown, f"{rule.name} uses fields our parsers never produce: {unknown}"


def test_rule_types_present():
    base = [r for r in RULES if isinstance(r, SigmaRule)]
    corr = {r.type.name.lower() for r in RULES if isinstance(r, SigmaCorrelationRule)}
    assert base
    assert {"event_count", "value_count", "temporal_ordered"} <= corr
