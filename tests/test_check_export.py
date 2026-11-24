import json
from pathlib import Path

from detlab import check_export, fixtures

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"


def _write(tmp_path: Path, records: list[dict]) -> Path:
    out = tmp_path / "export.json"
    out.write_text(json.dumps(records), encoding="utf-8")
    return out


def _all_fixture_events() -> list[dict]:
    events: list[dict] = []
    for fixture in fixtures.load_fixtures(ROOT / "tests" / "fixtures").values():
        for case in fixture.cases:
            events.extend(case.raw_events)
    return events


def _rule(report: check_export.ExportReport, name: str) -> check_export.RuleReport:
    return next(r for r in report.rules if r.rule == name)


def test_fixture_events_have_no_schema_problems(tmp_path: Path) -> None:
    report = check_export.check(RULES, [_write(tmp_path, _all_fixture_events())])
    assert not report.skipped
    assert all(r.records for r in report.rules), "every rule should see some fixture records"
    assert [p for r in report.rules for p in r.problems] == []
    assert check_export.print_report(report) == 0


def test_casing_difference_is_reported(tmp_path: Path) -> None:
    record = {
        "activityDisplayName": "Add member to role",
        "activityDateTime": "2026-12-01T00:00:00Z",
        "Result": "success",
    }
    report = check_export.check(RULES, [_write(tmp_path, [record])])
    rule = _rule(report, "entra_privileged_role_assigned")
    assert any("Result exists (casing differs)" in p for p in rule.problems)
    assert check_export.print_report(report) == 1


def test_array_field_is_reported(tmp_path: Path) -> None:
    record = {"createdDateTime": "2026-12-01T00:00:00Z", "userPrincipalName": "a@lab.example", "status": {"errorCode": [50126, 0]}}
    report = check_export.check(RULES, [_write(tmp_path, [record])])
    rule = _rule(report, "entra_repeated_failed_signins")
    assert any("status.errorCode is an array" in p for p in rule.problems)


def test_missing_field_is_only_a_note(tmp_path: Path) -> None:
    record = {"createdDateTime": "2026-12-01T00:00:00Z", "userPrincipalName": "a@lab.example"}
    report = check_export.check(RULES, [_write(tmp_path, [record])])
    rule = _rule(report, "entra_repeated_failed_signins")
    assert rule.problems == []
    assert any(n.startswith("status.errorCode is in no record") for n in rule.notes)


def test_unrecognised_records_fail_the_check(tmp_path: Path) -> None:
    report = check_export.check(RULES, [_write(tmp_path, [{"Id": "x", "CreatedDateTime": "2026-12-01T00:00:00Z"}])])
    assert len(report.skipped) == 1
    assert check_export.print_report(report) == 1
