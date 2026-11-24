"""Test fixtures: sample events that each rule must (or must not) alert on.

One YAML file per deployed rule, in tests/fixtures/<rule name>.yml::

    rule: aws_root_console_login
    cases:
      - name: root signs in to the console
        expect: alert            # or no_alert
        events:
          - {...raw CloudTrail record...}
          - repeat: 10           # optional: copy an event N times,
            every_seconds: 30    # moving its timestamp and ID each time
            event: {...}

Events are raw records, exactly as they appear in the log source. They are normalised by
detlab.normalize before evaluation, just like at ingest.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from detlab import normalize, sigma_eval

EXPECTATIONS = ("alert", "no_alert")


@dataclass
class Case:
    name: str
    expect: str
    raw_events: list[dict[str, Any]]

    @property
    def events(self) -> list[dict[str, Any]]:
        return [normalize.normalize(e)[1] for e in self.raw_events]


@dataclass
class Fixture:
    rule: str
    path: Path
    cases: list[Case] = field(default_factory=list)


@dataclass
class CaseResult:
    rule: str
    case: str
    expect: str
    got: str | None
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.error is None and self.got == self.expect


def _shift_time(value: str, seconds: float) -> str:
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00")) + timedelta(seconds=seconds)
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def _expand(items: list[Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict) and "repeat" in item:
            template = item["event"]
            source = normalize.detect_source(template)
            time_field = normalize.TIME_FIELD[source]
            id_field = normalize.ID_FIELD[source]
            for i in range(int(item["repeat"])):
                event = copy.deepcopy(template)
                event[time_field] = _shift_time(template[time_field], i * float(item.get("every_seconds", 1)))
                if event.get(id_field):
                    event[id_field] = f"{event[id_field]}-{i:03d}"
                events.append(event)
        else:
            events.append(item)
    return events


def load_fixture(path: Path) -> Fixture:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    fixture = Fixture(rule=data["rule"], path=path)
    for raw in data.get("cases") or []:
        expect = raw.get("expect")
        if expect not in EXPECTATIONS:
            raise ValueError(f"{path.name}: case {raw.get('name')!r} has expect={expect!r}")
        fixture.cases.append(Case(name=raw["name"], expect=expect, raw_events=_expand(raw["events"])))
    return fixture


def load_fixtures(fixtures_dir: Path) -> dict[str, Fixture]:
    fixtures: dict[str, Fixture] = {}
    for path in sorted(fixtures_dir.glob("*.yml")):
        fixture = load_fixture(path)
        if fixture.rule in fixtures:
            raise ValueError(f"two fixture files for rule {fixture.rule}")
        fixtures[fixture.rule] = fixture
    return fixtures


def run_offline(rules_dir: Path, fixtures_dir: Path) -> list[CaseResult]:
    collection = sigma_eval.load_rules(rules_dir)
    rules = {sigma_eval.rule_name(r): r for r in sigma_eval.deployed_rules(collection)}
    results: list[CaseResult] = []
    for name, fixture in load_fixtures(fixtures_dir).items():
        rule = rules.get(name)
        for case in fixture.cases:
            if rule is None:
                results.append(CaseResult(name, case.name, case.expect, None, "no deployed rule with this name"))
                continue
            try:
                hits = sigma_eval.alerts_for(rule, case.events)
                got = "alert" if hits else "no_alert"
                results.append(CaseResult(name, case.name, case.expect, got))
            except Exception as exc:  # noqa: BLE001 - reported per case
                results.append(CaseResult(name, case.name, case.expect, None, f"{type(exc).__name__}: {exc}"))
    return results
