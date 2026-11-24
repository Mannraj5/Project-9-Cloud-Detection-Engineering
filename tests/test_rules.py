"""Every fixture case must give the expected result, and the repo must pass its own lint."""

from pathlib import Path

import pytest

from detlab import fixtures, lint

ROOT = Path(__file__).resolve().parents[1]
RESULTS = fixtures.run_offline(ROOT / "rules", ROOT / "tests" / "fixtures")


@pytest.mark.parametrize("result", RESULTS, ids=lambda r: f"{r.rule}::{r.case}")
def test_fixture_case(result: fixtures.CaseResult) -> None:
    assert result.error is None, result.error
    assert result.got == result.expect


def test_every_rule_has_cases() -> None:
    assert len({r.rule for r in RESULTS}) >= 8


def test_repository_lint() -> None:
    assert lint.lint(ROOT) == []
