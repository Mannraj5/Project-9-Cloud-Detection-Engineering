"""Unit tests for the evaluator's ES|QL semantics, independent of the lab rules."""

from sigma.collection import SigmaCollection

from detlab import sigma_eval

RULE = """
title: t
id: 00000000-0000-4000-8000-000000000001
name: t
status: test
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    eventName: ConsoleLogin
  filter:
    awsRegion: ap-southeast-2
  condition: selection and not filter
level: low
"""


def _rule(text: str = RULE):
    return SigmaCollection.from_yaml(text).rules[0]


def test_basic_match_and_filter() -> None:
    rule = _rule()
    assert sigma_eval.rule_matches(rule, {"eventName": "ConsoleLogin", "awsRegion": "us-east-1"})
    assert not sigma_eval.rule_matches(rule, {"eventName": "ConsoleLogin", "awsRegion": "ap-southeast-2"})


def test_string_match_is_case_sensitive_like_esql() -> None:
    assert not sigma_eval.rule_matches(_rule(), {"eventName": "consolelogin", "awsRegion": "us-east-1"})


def test_missing_field_in_filter_is_null_not_false() -> None:
    # Sigma would say "not filter" is true here; ES|QL says null, so no row.
    assert not sigma_eval.rule_matches(_rule(), {"eventName": "ConsoleLogin"})


def test_multi_valued_field_never_matches() -> None:
    rule = _rule(RULE.replace("condition: selection and not filter", "condition: selection"))
    assert sigma_eval.rule_matches(rule, {"eventName": "ConsoleLogin"})
    assert not sigma_eval.rule_matches(rule, {"eventName": ["ConsoleLogin", "Other"]})


def test_wildcards_and_null() -> None:
    rule = _rule(
        RULE.replace("eventName: ConsoleLogin", "eventName|startswith: Console\n    errorCode: null").replace(
            "condition: selection and not filter", "condition: selection"
        )
    )
    assert sigma_eval.rule_matches(rule, {"eventName": "ConsoleLogin"})
    assert not sigma_eval.rule_matches(rule, {"eventName": "ConsoleLogin", "errorCode": "AccessDenied"})
    assert not sigma_eval.rule_matches(rule, {"eventName": "SwitchRole"})


def test_field_values_walks_lists() -> None:
    event = {"a": [{"b": 1}, {"b": 2}], "c": None}
    assert sigma_eval.field_values(event, "a.b") == [1, 2]
    assert sigma_eval.single_value(event, "a.b") is None
    assert sigma_eval.single_value(event, "c") is None
