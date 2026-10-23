"""Convert our Sigma rules to KQL for Microsoft Sentinel (ASIM normalized schema).

Two parts, both on pySigma's official extension points:
  * asim_pipeline(): a processing pipeline that rewrites our ECS field names and values
    into ASIM (Advanced Security Information Model) and picks the ASIM parser to query.
  * KqlBackend: a TextQueryBackend that writes KQL tokens and correlation templates.

Why our own backend: the official Kusto backend (pysigma-backend-kusto 1.0.1) requires
pySigma < 2.0, and our engine is built on pySigma 2.0. See ADR 0005.

Known difference from our Python engine: KQL correlations here use tumbling windows
(bin(TimeGenerated, 5m)), while the engine uses sliding windows. A burst that straddles a
bin boundary can be split and missed. Documented in ADR 0005 and tested.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from sigma.conditions import ConditionNOT
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.correlations import SigmaCorrelationConditionOperator, SigmaCorrelationRule
from sigma.processing.conditions import IncludeFieldCondition, LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    FieldMappingTransformation,
    MapStringTransformation,
    SetStateTransformation,
)
from sigma.types import CompareOperators

from soclab.detections.engine import load_rule_collection
from soclab.detections.models import rule_key

# ASIM parsers (unifying functions) per log source.
ASIM_TABLES = {
    ("linux", "sshd", None): "imAuthentication",
    ("linux", None, "firewall"): "imNetworkSession",
}

AUTH_FIELDS = {
    "event.action": "EventType",
    "event.outcome": "EventResult",
    "user.name": "TargetUsername",
    "source.ip": "SrcIpAddr",
    "source.port": "SrcPortNumber",
    "host.name": "DvcHostname",
}
NETWORK_FIELDS = {
    "event.action": "DvcAction",
    "event.outcome": "EventResult",
    "source.ip": "SrcIpAddr",
    "source.port": "SrcPortNumber",
    "destination.ip": "DstIpAddr",
    "destination.port": "DstPortNumber",
    "network.transport": "NetworkProtocol",
    "host.name": "DvcHostname",
}
VALUES = {
    "event.action": {"ssh_login": "Logon", "firewall_block": "Deny", "firewall_allow": "Allow"},
    "event.outcome": {"success": "Success", "failure": "Failure"},
}


def asim_pipeline() -> ProcessingPipeline:
    items: list[ProcessingItem] = []
    # Values first, while fields still have their ECS names.
    for field, mapping in VALUES.items():
        items.append(
            ProcessingItem(
                MapStringTransformation(mapping),  # type: ignore[arg-type]
                identifier=f"asim_values_{field}",
                field_name_conditions=[IncludeFieldCondition([field])],
            )
        )
    for (product, service, category), table in ASIM_TABLES.items():

        def ls(p=product, s=service, c=category) -> LogsourceCondition:
            return LogsourceCondition(product=p, service=s, category=c)  # one instance per item

        fields = AUTH_FIELDS if table == "imAuthentication" else NETWORK_FIELDS
        items += [
            ProcessingItem(SetStateTransformation("table", table), rule_conditions=[ls()]),
            ProcessingItem(FieldMappingTransformation(fields), rule_conditions=[ls()]),  # type: ignore[arg-type]
        ]
    return ProcessingPipeline(name="ECS to ASIM", priority=20, items=items)


class KqlBackend(TextQueryBackend):
    name: ClassVar[str] = "KQL (Microsoft Sentinel, ASIM)"
    formats: ClassVar[dict[str, str]] = {"default": "KQL query"}
    requires_pipeline: ClassVar[bool] = False

    query_expression: ClassVar[str] = "{state[table]}\n| where {query}"
    state_defaults: ClassVar[dict[str, str]] = {"table": "UNMAPPED_LOGSOURCE"}

    group_expression: ClassVar[str] = "({expr})"
    token_separator: str = " "
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"
    eq_token: ClassVar[str] = " =~ "  # Sigma strings are case-insensitive; == would be cased

    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    add_escaped: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "*"
    bool_values: ClassVar[dict[bool, str | None]] = {True: "true", False: "false"}

    startswith_expression: ClassVar[str] = "{field} startswith {value}"
    endswith_expression: ClassVar[str] = "{field} endswith {value}"
    contains_expression: ClassVar[str] = "{field} contains {value}"
    case_sensitive_match_expression: ClassVar[str] = "{field} == {value}"
    case_sensitive_startswith_expression: ClassVar[str] = "{field} startswith_cs {value}"
    case_sensitive_endswith_expression: ClassVar[str] = "{field} endswith_cs {value}"
    case_sensitive_contains_expression: ClassVar[str] = "{field} contains_cs {value}"
    re_expression: ClassVar[str] = '{field} matches regex "{regex}"'
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[list[str]] = ['"']
    cidr_expression: ClassVar[str] = 'ipv4_is_in_range({field}, "{value}")'
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[dict[CompareOperators, str]] = {
        CompareOperators.LT: "<",
        CompareOperators.LTE: "<=",
        CompareOperators.GT: ">",
        CompareOperators.GTE: ">=",
        CompareOperators.NEQ: "!=",
    }
    field_null_expression: ClassVar[str] = "isempty({field})"
    field_exists_expression: ClassVar[str] = "isnotempty({field})"
    field_not_exists_expression: ClassVar[str] = "isempty({field})"

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"
    or_in_operator: ClassVar[str] = "in~"
    list_separator: ClassVar[str] = ", "

    unbound_value_str_expression: ClassVar[str] = "* has {value}"
    unbound_value_num_expression: ClassVar[str] = "* has {value}"

    # ---- correlations: summarize over tumbling windows ---------------------------
    correlation_methods: ClassVar[dict[str, str]] = {"default": "summarize over time bins"}
    default_correlation_method: ClassVar[str] = "default"
    default_correlation_query: ClassVar[dict[str, str]] = {
        "default": "{search}\n{aggregate}\n{condition}"
    }
    correlation_search_single_rule_expression: ClassVar[str] = "{query}"
    correlation_search_multi_rule_expression: ClassVar[str] = "union\n{queries}"
    correlation_search_multi_rule_query_expression: ClassVar[str] = (
        '({query}\n| extend EventRule = "{ruleid}")'
    )
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = ",\n"

    timespan_mapping: ClassVar[dict[str, str]] = {"M": "30d", "y": "365d"}
    groupby_expression: ClassVar[dict[str, str]] = {"default": ", {fields}"}
    groupby_field_expression: ClassVar[dict[str, str]] = {"default": "{field}"}
    groupby_field_expression_joiner: ClassVar[dict[str, str]] = {"default": ", "}
    groupby_expression_nofield: ClassVar[dict[str, str]] = {"default": ""}

    event_count_aggregation_expression: ClassVar[dict[str, str]] = {
        "default": "| summarize EventCount = count() by bin(TimeGenerated, {timespan}){groupby}"
    }
    value_count_aggregation_expression: ClassVar[dict[str, str]] = {
        "default": "| summarize ValueCount = dcount({field}) by bin(TimeGenerated, {timespan})"
        "{groupby}"
    }
    referenced_rules_expression: ClassVar[dict[str, str]] = {"default": '"{ruleid}"'}
    referenced_rules_expression_joiner: ClassVar[dict[str, str]] = {"default": ", "}

    event_count_condition_expression: ClassVar[dict[str, str]] = {
        "default": "| where EventCount {op} {count}"
    }
    value_count_condition_expression: ClassVar[dict[str, str]] = {
        "default": "| where ValueCount {op} {count}"
    }
    correlation_condition_mapping: ClassVar[dict[SigmaCorrelationConditionOperator, str | None]] = {
        SigmaCorrelationConditionOperator.LT: "<",
        SigmaCorrelationConditionOperator.LTE: "<=",
        SigmaCorrelationConditionOperator.GT: ">",
        SigmaCorrelationConditionOperator.GTE: ">=",
        SigmaCorrelationConditionOperator.EQ: "==",
        SigmaCorrelationConditionOperator.NEQ: "!=",
    }

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState):
        """KQL's not() is a function: always wrap the negated expression."""
        inner = self.convert_condition(cond.args[0], state)
        return f"not({inner})"

    def finish_query(self, rule, query, state):
        """Only base rules get the "<table> | where" frame; correlations embed theirs."""
        if isinstance(rule, SigmaCorrelationRule):
            return query
        return super().finish_query(rule, query, state)

    def convert_correlation_temporal_ordered_rule(
        self, rule: SigmaCorrelationRule, output_format: str | None = None, method: str = "default"
    ) -> list[str]:
        """Each stage happened, in order: earliest first stage <= ... <= latest last stage.

        Templates cannot express per-stage timestamps, so this one is written by hand.
        """
        search = self.convert_correlation_search(rule)
        span = self.convert_timespan(rule.timespan, method)
        groupby = self.convert_correlation_aggregation_groupby_from_template(rule.group_by, method)
        names = [rule_key(ref.rule) for ref in rule.rules or []]
        last = len(names) - 1
        stages = ", ".join(
            f'T{i} = {"maxif" if i == last else "minif"}(TimeGenerated, EventRule == "{n}")'
            for i, n in enumerate(names)
        )
        order = " and ".join(f"T{i} <= T{i + 1}" for i in range(last))
        return [f"{search}\n| summarize {stages} by bin(TimeGenerated, {span}){groupby}\n"
                f"| where {order}"]  # fmt: skip


def convert_rules(rules_dir: str | Path = "rules") -> dict[str, str]:
    """Rule name -> KQL query for every rule that pySigma marks as an output rule.

    Correlation queries embed the converted queries of the rules they reference, so
    base rules are converted first and correlations in dependency order (as our engine
    runs them).
    """
    collection = load_rule_collection(rules_dir)
    collection.resolve_rule_references()
    backend = KqlBackend(processing_pipeline=asim_pipeline())  # type: ignore[arg-type]  # pySigma typing quirk; runtime OK
    backend.init_processing_pipeline("default")  # what backend.convert() does first

    ordered: list = [r for r in collection.rules if not isinstance(r, SigmaCorrelationRule)]
    seen: set[int] = set()

    def visit(rule) -> None:
        if id(rule) in seen or not isinstance(rule, SigmaCorrelationRule):
            return
        seen.add(id(rule))
        for ref in rule.rules or []:
            visit(ref.rule)
        ordered.append(rule)

    for rule in collection.rules:
        visit(rule)

    out = {}
    for rule in ordered:
        if isinstance(rule, SigmaCorrelationRule):
            queries = backend.convert_correlation_rule(rule)
        else:
            queries = backend.convert_rule(rule)
        if rule._output:  # silenced building blocks are not deployed on their own
            out[rule_key(rule)] = "\n".join(str(q) for q in queries)
    return out


def render_file(rule, query: str, source: str) -> str:
    """KQL file with a header that says where it came from."""
    techniques = ", ".join(t.name.upper() for t in rule.tags if t.name.startswith("t"))
    return (
        f"// {rule.title}\n"
        f"// Generated from {source} by `python -m soclab.kql`. Do not edit by hand.\n"
        f"// Level: {rule.level.name.lower() if rule.level else 'n/a'}"
        f" | ATT&CK: {techniques or 'n/a'} | Schema: Microsoft Sentinel ASIM\n"
        f"{query}\n"
    )


def write_kql(rules_dir: str | Path = "rules", out_dir: str | Path = "kql") -> list[Path]:
    collection = load_rule_collection(rules_dir)
    by_name = {rule_key(r): r for r in collection.rules}
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, query in convert_rules(rules_dir).items():
        path = out / f"{name}.kql"
        rule = by_name[name]
        # Path relative to the repo root, whatever directory the command runs from.
        if rule.source and rule.source.path:
            src = Path(rule.source.path).resolve().relative_to(Path(rules_dir).resolve().parent)
            source = src.as_posix()
        else:
            source = name
        path.write_text(render_file(rule, query, source))
        written.append(path)
    return written


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(
        prog="python -m soclab.kql", description="Convert Sigma rules to KQL (Sentinel ASIM)."
    )
    ap.add_argument("--rules", default="rules")
    ap.add_argument("--out", default="kql")
    args = ap.parse_args()
    for path in write_kql(args.rules, args.out):
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
