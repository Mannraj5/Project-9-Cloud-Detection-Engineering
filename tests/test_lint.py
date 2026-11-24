from pathlib import Path

from detlab import lint


def test_redaction_flags_real_looking_values(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "x.yml").write_text(
        "accountId: '123456789012'\n"
        "key: AKIAABCDEFGHIJKLMNOP\n"
        "upn: someone@realcompany.com.au\n"
        "ok: '111111111111' AKIAEXAMPLEEXAMPLE00 student@lab.example\n",
        encoding="utf-8",
    )
    problems = lint.redaction_problems(tmp_path)
    assert len(problems) == 3
    assert any("account ID" in p for p in problems)
    assert any("access key" in p for p in problems)
    assert any("realcompany.com.au" in p for p in problems)


def test_redaction_ignores_ids_inside_arns_and_uuids(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "x.yml").write_text("id: 00000000-0000-4000-8000-000000000801\n", encoding="utf-8")
    assert lint.redaction_problems(tmp_path) == []
