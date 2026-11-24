"""Check real log exports against the fields the rules use, before ingesting them.

The fixtures were written from the Microsoft Graph and CloudTrail schemas. A real export
can differ (another field name, different casing, a field that is an array), and in ES|QL
each of those makes a rule silently match nothing. This check reads the files offline,
normalises them exactly like ``detlab ingest`` and reports, for every deployed rule:

* how many records of the rule's log source have each field the rule uses,
* how many hold it as an array (ES|QL compares those as null, so they never match),
* fields that are missing but exist with different casing (a likely rename),
* how many records the rule's detection matches (correlations: the base rule).

Only counts and field names are printed, never values, so the output is safe to paste or
screenshot.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from detlab import lint, normalize, sigma_eval

SERVICE_SOURCE = {
    "cloudtrail": normalize.CLOUDTRAIL,
    "signinlogs": normalize.ENTRA_SIGNIN,
    "auditlogs": normalize.ENTRA_AUDIT,
}


@dataclass
class FieldStat:
    name: str
    present: int = 0
    multi: int = 0
    case_variants: set[str] = field(default_factory=set)


@dataclass
class RuleReport:
    rule: str
    source: str
    records: int
    fields: list[FieldStat]
    matches: int

    @property
    def problems(self) -> list[str]:
        """Things that are almost certainly a schema mismatch."""
        out = []
        for f in self.fields:
            if f.present == 0 and f.case_variants:
                out.append(f"{f.name} not found, but {', '.join(sorted(f.case_variants))} exists (casing differs)")
            if f.multi:
                out.append(f"{f.name} is an array in {f.multi} records (ES|QL treats it as null)")
        return out

    @property
    def notes(self) -> list[str]:
        """Missing fields that may just mean the export has no events of that kind."""
        return [
            f"{f.name} is in no record (fine if no such event happened in this export)"
            for f in self.fields
            if f.present == 0 and not f.case_variants
        ]


@dataclass
class ExportReport:
    records: Counter[str] = field(default_factory=Counter)
    skipped: list[str] = field(default_factory=list)
    rules: list[RuleReport] = field(default_factory=list)


def _source_of(rule: SigmaRule | SigmaCorrelationRule) -> str | None:
    if isinstance(rule, SigmaCorrelationRule):
        rule = rule.rules[0].rule
    return SERVICE_SOURCE.get(rule.logsource.service or "")


def _paths(value: Any, prefix: str = "") -> set[str]:
    """Every dotted leaf path in a record, walking arrays like field_values() does."""
    out: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            out |= _paths(item, f"{prefix}{key}.")
    elif isinstance(value, list):
        for item in value:
            out |= _paths(item, prefix)
    elif prefix:
        out.add(prefix[:-1])
    return out


def _base_rules(rule: SigmaRule | SigmaCorrelationRule) -> list[SigmaRule]:
    if isinstance(rule, SigmaCorrelationRule):
        return [ref.rule for ref in rule.rules if isinstance(ref.rule, SigmaRule)]
    return [rule]


def check(rules_dir: Path, paths: list[Path]) -> ExportReport:
    report = ExportReport()
    docs: dict[str, list[dict[str, Any]]] = {}
    for file, record in normalize.iter_records(paths):
        try:
            source, doc = normalize.normalize(record)
        except normalize.UnknownRecordError as exc:
            report.skipped.append(f"{file.name}: {exc}")
            continue
        report.records[source] += 1
        docs.setdefault(source, []).append(doc)

    collection = sigma_eval.load_rules(rules_dir)
    for rule in sigma_eval.deployed_rules(collection):
        source = _source_of(rule)
        if source is None:
            continue
        records = docs.get(source, [])
        all_paths: set[str] = set()
        for doc in records:
            all_paths |= _paths(doc)
        lower = {}
        for p in all_paths:
            lower.setdefault(p.lower(), set()).add(p)

        stats = []
        for name in sorted(lint.rule_fields(rule)):
            stat = FieldStat(name)
            for doc in records:
                values = sigma_eval.field_values(doc, name)
                if values is sigma_eval._MISSING:
                    continue
                stat.present += 1
                if len(values) > 1:  # type: ignore[arg-type]
                    stat.multi += 1
            if stat.present == 0:
                stat.case_variants = lower.get(name.lower(), set()) - {name}
            stats.append(stat)

        bases = _base_rules(rule)
        matches = sum(1 for doc in records if any(sigma_eval.rule_matches(b, doc) for b in bases))
        report.rules.append(RuleReport(sigma_eval.rule_name(rule), source, len(records), stats, matches))
    return report


def print_report(report: ExportReport) -> int:
    print("Records by source:")
    for source in normalize.INDEX:
        print(f"  {source:<13} {report.records[source]}")
    if report.skipped:
        print(f"\n{len(report.skipped)} records not recognised (first 10):")
        for line in report.skipped[:10]:
            print(f"  {line}")

    problems = 0
    print("\nRules:")
    for r in report.rules:
        if r.records == 0:
            print(f"  --    {r.rule}: no {r.source} records in these files")
            continue
        issues = r.problems
        problems += len(issues)
        mark = "OK  " if not issues else "WARN"
        print(f"  {mark}  {r.rule}: {r.records} records, detection matches {r.matches}")
        for f in r.fields:
            extra = f", {f.multi} as array" if f.multi else ""
            print(f"          {f.name}: in {f.present}/{r.records}{extra}")
        for issue in issues:
            print(f"          ! {issue}")
        for note in r.notes:
            print(f"          ? {note}")

    if report.skipped or problems:
        print("\nFix the fixture or the rule so it matches the real field names, then re-run.")
        return 1
    print("\nEvery field the rules use is present and single-valued.")
    return 0
