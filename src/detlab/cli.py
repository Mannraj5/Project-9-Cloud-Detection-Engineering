"""Command line: detlab test | lint | convert | coverage | kibana | check-export | ingest | live-validate."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from detlab import check_export, convert, coverage, fixtures, lint, live
from detlab.es import Elastic, ElasticError
from detlab.ingest import ingest


def _root(args: argparse.Namespace) -> Path:
    return Path(args.root).resolve()


def _print_results(results: list[fixtures.CaseResult]) -> int:
    width = max((len(r.rule) for r in results), default=10)
    for r in results:
        mark = "PASS" if r.passed else "FAIL"
        detail = f"expected {r.expect}, got {r.got}" if r.error is None else r.error
        print(f"{mark}  {r.rule:<{width}}  {r.case}" + ("" if r.passed else f"  -> {detail}"))
    failed = [r for r in results if not r.passed]
    rules = len({r.rule for r in results})
    print(f"\n{len(results) - len(failed)}/{len(results)} cases passed across {rules} rules.")
    return 1 if failed or not results else 0


def cmd_test(args: argparse.Namespace) -> int:
    root = _root(args)
    return _print_results(fixtures.run_offline(root / "rules", root / "tests" / "fixtures"))


def cmd_lint(args: argparse.Namespace) -> int:
    problems = lint.lint(_root(args))
    for p in problems:
        print(f"- {p}")
    print("lint: OK" if not problems else f"\nlint: {len(problems)} problem(s)")
    return 1 if problems else 0


def cmd_convert(args: argparse.Namespace) -> int:
    root = _root(args)
    written = convert.write_esql(root / "rules", root / "pipelines" / "detlab-esql.yml", root / "elastic" / "esql")
    for path in written:
        print(f"wrote {path.relative_to(root).as_posix()}")
    return 0


def cmd_kibana(args: argparse.Namespace) -> int:
    root = _root(args)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    content = convert.kibana_ndjson(root / "rules", root / "pipelines" / "detlab-esql.yml", args.interval, args.lookback)
    out.write_text(content, encoding="utf-8", newline="\n")
    print(f"wrote {len(content.splitlines())} rules to {out}")
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    out = coverage.write(_root(args))
    print(f"wrote {out.relative_to(_root(args)).as_posix()}")
    return 0


def cmd_check_export(args: argparse.Namespace) -> int:
    report = check_export.check(_root(args) / "rules", [Path(p) for p in args.paths])
    return check_export.print_report(report)


def cmd_ingest(args: argparse.Namespace) -> int:
    root = _root(args)
    es = Elastic(args.es_url)
    report = ingest(es, [Path(p) for p in args.paths], root / "elastic" / "index-template.json")
    for index, count in sorted(report.indexed.items()):
        print(f"{index}: {count} documents sent")
    for line in report.skipped[:20]:
        print(f"skipped {line}")
    for line in report.errors[:20]:
        print(f"error {line}")
    if report.errors:
        print(f"\n{len(report.errors)} documents were rejected by Elasticsearch.")
    return 1 if report.errors else 0


def cmd_live(args: argparse.Namespace) -> int:
    root = _root(args)
    es = Elastic(args.es_url)
    try:
        results = live.run_live(
            es,
            root / "rules",
            root / "tests" / "fixtures",
            root / "pipelines" / "detlab-esql.yml",
            root / "elastic" / "index-template.json",
        )
    except ElasticError as exc:
        print(exc)
        return 1
    return _print_results(results)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="detlab", description=__doc__)
    parser.add_argument("--root", default=".", help="repository root (default: current folder)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("test", help="run every fixture case through the offline evaluator").set_defaults(func=cmd_test)
    sub.add_parser("lint", help="check rule metadata, fixtures, field mappings and generated ES|QL").set_defaults(func=cmd_lint)
    sub.add_parser("convert", help="regenerate elastic/esql from the Sigma rules").set_defaults(func=cmd_convert)
    sub.add_parser("coverage", help="regenerate docs/coverage-matrix.md").set_defaults(func=cmd_coverage)

    p_kibana = sub.add_parser("kibana", help="build an Elastic Security rule import file (needs internet for ATT&CK data)")
    p_kibana.add_argument("-o", "--output", default="build/kibana-rules.ndjson")
    p_kibana.add_argument("--interval", type=int, default=10, help="how often each rule runs, in minutes (default 10)")
    p_kibana.add_argument(
        "--lookback",
        type=int,
        default=60,
        help="how far back non-correlation rules search, in minutes (default 60; correlation rules always use --interval)",
    )
    p_kibana.set_defaults(func=cmd_kibana)

    p_check = sub.add_parser("check-export", help="check real log files against the fields the rules use (offline)")
    p_check.add_argument("paths", nargs="+", help="files or folders (.json, .json.gz, .jsonl)")
    p_check.set_defaults(func=cmd_check_export)

    p_ingest = sub.add_parser("ingest", help="load CloudTrail / Entra JSON files into Elasticsearch")
    p_ingest.add_argument("paths", nargs="+", help="files or folders (.json, .json.gz, .jsonl)")
    p_ingest.add_argument("--es-url", help="default: $ES_URL or http://localhost:9200")
    p_ingest.set_defaults(func=cmd_ingest)

    p_live = sub.add_parser("live-validate", help="run the fixtures against a real Elasticsearch (uses detlabtest-* indices only)")
    p_live.add_argument("--es-url", help="default: $ES_URL or http://localhost:9200")
    p_live.set_defaults(func=cmd_live)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
