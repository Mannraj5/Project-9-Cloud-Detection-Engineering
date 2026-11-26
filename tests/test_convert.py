"""Schedule and look-back of the Kibana export (see design-notes.md, "Schedule and look-back")."""

from pathlib import Path

import pytest

from detlab import convert

ROOT = Path(__file__).resolve().parents[1]
QUERIES = convert.rendered_files(ROOT / "rules", ROOT / "pipelines" / "detlab-esql.yml")


def _rule(query: str) -> dict:
    return {"query": query, "interval": "5m", "from": "now-5m", "to": "now"}


def test_plain_rule_gets_the_long_lookback() -> None:
    rule = convert.apply_lookback(_rule("from detlab-cloudtrail metadata _id | where eventName == \"StopLogging\""), 10, 60)
    assert (rule["interval"], rule["from"], rule["to"]) == ("10m", "now-60m", "now")


def test_aggregating_rule_keeps_lookback_equal_to_interval() -> None:
    query = "from detlab-entra-audit metadata _id\n| eval b=date_trunc(10minutes, @timestamp) | STATS n=count() by b\n| where n >= 5"
    rule = convert.apply_lookback(_rule(query), 10, 60)
    assert (rule["interval"], rule["from"]) == ("10m", "now-10m")


def test_lookback_shorter_than_interval_is_refused() -> None:
    with pytest.raises(ValueError):
        convert.apply_lookback(_rule("from detlab-cloudtrail"), 10, 5)


def test_exactly_the_correlation_rules_are_aggregating() -> None:
    aggregating = sorted(name for name, text in QUERIES.items() if convert.is_aggregating(text))
    assert aggregating == ["entra_mass_user_disable.esql", "entra_repeated_failed_signins.esql"]
