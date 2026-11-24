"""Repository checks that `sigma check` does not cover.

* Every deployed rule has the metadata an analyst needs (description, false positives,
  severity, at least one ATT&CK technique) and lives in a file named after it.
* Every deployed rule has fixtures with at least one alert case and one no-alert case.
* Every field a rule uses is mapped explicitly in the index template. Without this, a
  query against an index that has never seen the field fails in ES|QL with
  "Unknown column" and the rule silently stops running.
* The committed ES|QL in elastic/esql and docs/coverage-matrix.md match what the rules
  generate today.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from sigma.conditions import ConditionFieldEqualsValueExpression
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from detlab import convert, coverage, fixtures, sigma_eval

TECHNIQUE_TAG = re.compile(r"^t\d{4}(\.\d{3})?$")


def _condition_fields(node: Any) -> set[str]:
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return {node.field}
    found: set[str] = set()
    for arg in getattr(node, "args", []) or []:
        found |= _condition_fields(arg)
    return found


def rule_fields(rule: SigmaRule | SigmaCorrelationRule) -> set[str]:
    if isinstance(rule, SigmaCorrelationRule):
        fields = set(rule.group_by or [])
        for ref in rule.rules:
            fields |= rule_fields(ref.rule)
        return fields
    fields: set[str] = set()
    for cond in rule.detection.parsed_condition:
        fields |= _condition_fields(cond.parse())
    return fields


def mapped_fields(template: dict[str, Any]) -> set[str]:
    out: set[str] = set()

    def walk(props: dict[str, Any], prefix: str) -> None:
        for name, spec in props.items():
            path = f"{prefix}{name}"
            if "type" in spec and spec["type"] != "object":
                out.add(path)
            if "properties" in spec:
                walk(spec["properties"], path + ".")

    walk(template["template"]["mappings"]["properties"], "")
    return out


# Placeholders that are allowed in committed sample data. Anything else that looks like an
# account ID, access key or email address is treated as a possible leak of real lab data.
ALLOWED_ACCOUNT_IDS = {"111111111111", "222222222222"}
ALLOWED_EMAIL_DOMAINS = {"lab.example", "example.com"}
ACCOUNT_ID = re.compile(r"(?<![\w-])\d{12}(?![\w-])")
ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
EMAIL = re.compile(r"\b[\w.+-]+@([\w-]+(?:\.[\w-]+)+)\b")
REDACTION_GLOBS = ("tests/fixtures/*.yml", "validation/*.yml", "evidence/**/*.md", "evidence/**/*.json")


def redaction_problems(root: Path) -> list[str]:
    problems = []
    for pattern in REDACTION_GLOBS:
        for path in sorted(root.glob(pattern)):
            rel = path.relative_to(root).as_posix()
            text = path.read_text(encoding="utf-8")
            for match in ACCOUNT_ID.findall(text):
                if match not in ALLOWED_ACCOUNT_IDS:
                    problems.append(f"{rel}: possible real AWS account ID {match[:4]}... (use 111111111111)")
            for match in ACCESS_KEY.findall(text):
                if "EXAMPLE" not in match:
                    problems.append(f"{rel}: possible real access key {match[:8]}...")
            for domain in EMAIL.findall(text):
                if domain.lower() not in ALLOWED_EMAIL_DOMAINS:
                    problems.append(f"{rel}: email domain '{domain}' (use @lab.example)")
    return problems


def lint(root: Path) -> list[str]:
    rules_dir = root / "rules"
    problems: list[str] = []
    collection = sigma_eval.load_rules(rules_dir)

    seen_ids: dict[str, str] = {}
    seen_names: set[str] = set()
    for rule in collection.rules:
        name = sigma_eval.rule_name(rule)
        if not rule.name:
            problems.append(f"{rule.title}: every rule needs a 'name'")
        if name in seen_names:
            problems.append(f"{name}: duplicate rule name")
        seen_names.add(name)
        if str(rule.id) in seen_ids:
            problems.append(f"{name}: id {rule.id} already used by {seen_ids[str(rule.id)]}")
        seen_ids[str(rule.id)] = name

    deployed = sigma_eval.deployed_rules(collection)
    for rule in deployed:
        name = sigma_eval.rule_name(rule)
        stem = Path(str(rule.source.path)).stem if rule.source else None
        if stem != name:
            problems.append(f"{name}: file is {stem}.yml, expected {name}.yml")
        for attr in ("description", "author", "date", "level"):
            if not getattr(rule, attr, None):
                problems.append(f"{name}: missing {attr}")
        if not rule.falsepositives:
            problems.append(f"{name}: list at least one false positive")
        techniques = [t for t in rule.tags if t.namespace == "attack" and TECHNIQUE_TAG.match(t.name)]
        if not techniques:
            problems.append(f"{name}: needs at least one ATT&CK technique tag (attack.tNNNN)")

    template = json.loads((root / "elastic" / "index-template.json").read_text(encoding="utf-8"))
    mapped = mapped_fields(template)
    for rule in deployed:
        for f in sorted(rule_fields(rule) - mapped):
            problems.append(f"{sigma_eval.rule_name(rule)}: field '{f}' is not mapped in elastic/index-template.json")

    loaded = fixtures.load_fixtures(root / "tests" / "fixtures")
    deployed_names = {sigma_eval.rule_name(r) for r in deployed}
    for name in sorted(deployed_names):
        fixture = loaded.get(name)
        if fixture is None:
            problems.append(f"{name}: no fixture file in tests/fixtures")
            continue
        expects = {c.expect for c in fixture.cases}
        for needed in fixtures.EXPECTATIONS:
            if needed not in expects:
                problems.append(f"{name}: fixtures need at least one '{needed}' case")
    for name in sorted(set(loaded) - deployed_names):
        problems.append(f"tests/fixtures/{loaded[name].path.name}: rule '{name}' is not a deployed rule")

    esql_dir = root / "elastic" / "esql"
    expected = convert.rendered_files(rules_dir, root / "pipelines" / "detlab-esql.yml")
    actual = {p.name: p.read_text(encoding="utf-8") for p in esql_dir.glob("*.esql")} if esql_dir.exists() else {}
    if expected != actual:
        problems.append("elastic/esql is out of date: run `detlab convert`")

    problems.extend(redaction_problems(root))

    matrix = root / "docs" / "coverage-matrix.md"
    if not matrix.exists() or matrix.read_text(encoding="utf-8") != coverage.build(root):
        problems.append("docs/coverage-matrix.md is out of date: run `detlab coverage`")

    return problems
