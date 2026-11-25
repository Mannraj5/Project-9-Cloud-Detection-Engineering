"""Run every fixture case against a real Elasticsearch with the generated ES|QL.

This is the proof that the offline evaluator is right: each case is loaded into fresh
``detlabtest-*`` indices and the converted query is run against them. Only those test
indices are created and deleted, never the real ``detlab-*`` data indices.
"""

from __future__ import annotations

from pathlib import Path

from detlab import convert, fixtures, normalize
from detlab.es import Elastic, ElasticError
from detlab.ingest import install_template

TEST_PREFIX = "detlabtest"


def _test_index(source: str) -> str:
    return normalize.INDEX[source].replace("detlab", TEST_PREFIX, 1)


def to_test_query(query: str) -> str:
    rewritten = query.replace("from detlab-", f"from {TEST_PREFIX}-", 1)
    if rewritten == query:
        raise ValueError("query does not read from a detlab-* index")
    return rewritten


def _recreate(es: Elastic, indices: list[str]) -> None:
    for index in indices:
        es.delete_index(index)
        es.create_index(index)


def _load(es: Elastic, by_index: dict[str, list[tuple[str | None, dict]]]) -> list[str]:
    errors: list[str] = []
    for index, docs in by_index.items():
        errors.extend(es.bulk_index(index, docs, refresh=True))
    return errors


def run_live(es: Elastic, rules_dir: Path, fixtures_dir: Path, pipeline_file: Path, template_file: Path) -> list[fixtures.CaseResult]:
    install_template(es, template_file)
    queries = convert.convert_rules(rules_dir, pipeline_file)
    test_indices = [_test_index(s) for s in normalize.INDEX]
    results: list[fixtures.CaseResult] = []

    # Create the test indices once and empty them between cases. Recreating them for every
    # case meant ~260 cluster-state changes, which timed out on a single node on an HDD.
    _recreate(es, test_indices)
    for name, fixture in fixtures.load_fixtures(fixtures_dir).items():
        for case in fixture.cases:
            if name not in queries:
                results.append(fixtures.CaseResult(name, case.name, case.expect, None, "no converted query"))
                continue
            for index in test_indices:
                es.clear_index(index)
            by_index: dict[str, list[tuple[str | None, dict]]] = {}
            for raw in case.raw_events:
                source, doc = normalize.normalize(raw)
                by_index.setdefault(_test_index(source), []).append((normalize.document_id(source, raw), doc))
            errors = _load(es, by_index)
            if errors:
                # A dynamic mapping left by an earlier case can clash with this one; retry on
                # fresh indices so each case is judged on its own events only.
                _recreate(es, test_indices)
                errors = _load(es, by_index)
            if errors:
                results.append(fixtures.CaseResult(name, case.name, case.expect, None, "; ".join(errors[:3])))
                continue
            try:
                response = es.esql(to_test_query(queries[name]))
            except ElasticError as exc:
                results.append(fixtures.CaseResult(name, case.name, case.expect, None, str(exc)))
                continue
            got = "alert" if response.get("values") else "no_alert"
            results.append(fixtures.CaseResult(name, case.name, case.expect, got))

    for index in test_indices:
        es.delete_index(index)
    return results
