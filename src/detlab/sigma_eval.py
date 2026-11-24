"""Evaluate Sigma rules against normalised events, offline, with ES|QL semantics.

pySigma parses the rules (the same parser the Elastic converter uses). This module only
walks the parsed condition tree. It copies how the converted ES|QL query behaves in
Elasticsearch, not the Sigma specification, because the point of the tests is to predict
what the SIEM will really do:

* Three-valued logic. A comparison on a missing field is null (unknown), not false, and
  NOT null is still null. A row only matches when the whole condition is true. So a filter
  on a field that is absent removes the event instead of letting it through.
* A comparison on a multi-valued field is null. (Checked against Elasticsearch 8.19.7:
  ``where field == "x"`` and ``like`` both return no rows when the field holds an array.)
* String matching is case-sensitive, and regular expressions must match the whole value
  (ES|QL ``rlike``).
* Correlation (event_count) rules count in fixed buckets (``date_trunc``), not a sliding
  window, exactly as the generated ES|QL does.
"""

from __future__ import annotations

import operator
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.correlations import SigmaCorrelationConditionOperator, SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCompareExpression,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

# Tri-state: True, False, or None (unknown / null).
Tri = bool | None

_MISSING = object()


class UnsupportedSigmaFeature(NotImplementedError):
    pass


def load_rules(rules_dir: Path) -> SigmaCollection:
    collection = SigmaCollection.load_ruleset([rules_dir])
    collection.resolve_rule_references()
    return collection


def rule_name(rule: SigmaRule | SigmaCorrelationRule) -> str:
    return rule.name or str(rule.id)


def deployed_rules(collection: SigmaCollection) -> list[SigmaRule | SigmaCorrelationRule]:
    """Rules that become alerts: correlation rules, plus detection rules that no
    correlation uses as a base rule (base rules are not converted on their own)."""
    base: set[str] = set()
    for rule in collection.rules:
        if isinstance(rule, SigmaCorrelationRule):
            for ref in rule.rules:
                base.add(rule_name(ref.rule))
    return [r for r in collection.rules if rule_name(r) not in base]


# ---------------------------------------------------------------- field access


def field_values(event: dict[str, Any], field: str) -> list[Any] | object:
    """All leaf values at a dotted path. Lists are walked, like Elasticsearch flattens
    arrays of objects. Returns _MISSING if the path is absent or null."""
    current: list[Any] = [event]
    for part in field.split("."):
        nxt: list[Any] = []
        for item in current:
            if isinstance(item, dict) and part in item:
                value = item[part]
                if isinstance(value, list):
                    nxt.extend(value)
                else:
                    nxt.append(value)
        current = nxt
    current = [v for v in current if v is not None]
    return current if current else _MISSING


def single_value(event: dict[str, Any], field: str) -> Any:
    """Value for ES|QL purposes: None if missing or multi-valued."""
    values = field_values(event, field)
    if values is _MISSING or len(values) != 1:  # type: ignore[arg-type]
        return None
    return values[0]  # type: ignore[index]


# ---------------------------------------------------------------- value matching


def _sigma_string_regex(value: SigmaString) -> re.Pattern[str]:
    parts = []
    for part in value.s:
        if part == SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            parts.append(re.escape(str(part)))
    return re.compile("".join(parts), re.DOTALL)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


_COMPARE = {
    CompareOperators.LT: operator.lt,
    CompareOperators.LTE: operator.le,
    CompareOperators.GT: operator.gt,
    CompareOperators.GTE: operator.ge,
}


def match_value(expected: Any, actual: Any) -> Tri:
    if isinstance(expected, SigmaNull):
        return actual is None
    if actual is None:
        return None
    if isinstance(expected, SigmaString):
        if not isinstance(actual, str):
            return False
        return _sigma_string_regex(expected).fullmatch(actual) is not None
    if isinstance(expected, SigmaBool):
        return isinstance(actual, bool) and actual == expected.boolean
    if isinstance(expected, SigmaNumber):
        return _is_number(actual) and actual == expected.number
    if isinstance(expected, SigmaRegularExpression):
        if not isinstance(actual, str):
            return False
        return re.fullmatch(str(expected.to_plain()), actual) is not None
    if isinstance(expected, SigmaCompareExpression):
        return _is_number(actual) and _COMPARE[expected.op](actual, expected.number.number)
    raise UnsupportedSigmaFeature(f"value type {type(expected).__name__} is not supported")


# ---------------------------------------------------------------- condition tree


def _tri_and(values: list[Tri]) -> Tri:
    if any(v is False for v in values):
        return False
    if any(v is None for v in values):
        return None
    return True


def _tri_or(values: list[Tri]) -> Tri:
    if any(v is True for v in values):
        return True
    if any(v is None for v in values):
        return None
    return False


def _evaluate(node: Any, event: dict[str, Any]) -> Tri:
    if isinstance(node, ConditionAND):
        return _tri_and([_evaluate(arg, event) for arg in node.args])
    if isinstance(node, ConditionOR):
        return _tri_or([_evaluate(arg, event) for arg in node.args])
    if isinstance(node, ConditionNOT):
        inner = _evaluate(node.args[0], event)
        return None if inner is None else not inner
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return match_value(node.value, single_value(event, node.field))
    raise UnsupportedSigmaFeature(f"condition element {type(node).__name__} is not supported")


def rule_matches(rule: SigmaRule, event: dict[str, Any]) -> bool:
    results = [_evaluate(cond.parse(), event) for cond in rule.detection.parsed_condition]
    return any(r is True for r in results)


# ---------------------------------------------------------------- correlation


def _epoch(event: dict[str, Any]) -> float:
    stamp = event.get("@timestamp")
    if not isinstance(stamp, str):
        raise ValueError("event has no @timestamp; normalise it first")
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


_CORRELATION_OPS = {
    SigmaCorrelationConditionOperator.LT: operator.lt,
    SigmaCorrelationConditionOperator.LTE: operator.le,
    SigmaCorrelationConditionOperator.GT: operator.gt,
    SigmaCorrelationConditionOperator.GTE: operator.ge,
    SigmaCorrelationConditionOperator.EQ: operator.eq,
    SigmaCorrelationConditionOperator.NEQ: operator.ne,
}


def correlation_alerts(rule: SigmaCorrelationRule, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if rule.type.name != "EVENT_COUNT":
        raise UnsupportedSigmaFeature(f"correlation type {rule.type.name} is not supported")
    span = rule.timespan.seconds
    counts: Counter[tuple[Any, ...]] = Counter()
    for event in events:
        if not any(rule_matches(ref.rule, event) for ref in rule.rules):
            continue
        bucket = int(_epoch(event) // span)
        group = tuple(single_value(event, f) for f in rule.group_by or [])
        counts[(bucket, *group)] += 1
    check = _CORRELATION_OPS[rule.condition.op]
    alerts = []
    for key, count in counts.items():
        if check(count, rule.condition.count):
            alerts.append({"bucket": key[0], "group": key[1:], "event_count": count})
    return alerts


def alerts_for(rule: SigmaRule | SigmaCorrelationRule, events: list[dict[str, Any]]) -> list[Any]:
    """What the deployed rule would alert on for this set of events."""
    if isinstance(rule, SigmaCorrelationRule):
        return correlation_alerts(rule, events)
    return [e for e in events if rule_matches(rule, e)]
