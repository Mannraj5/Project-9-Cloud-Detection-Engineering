"""Load CloudTrail and Entra log files into Elasticsearch."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from detlab import normalize
from detlab.es import Elastic

TEMPLATE_NAME = "detlab"
BATCH = 500


@dataclass
class IngestReport:
    # Documents sent per index. Any that Elasticsearch rejected are listed in errors.
    indexed: Counter[str] = field(default_factory=Counter)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def install_template(es: Elastic, template_file: Path) -> None:
    es.put_index_template(TEMPLATE_NAME, json.loads(template_file.read_text(encoding="utf-8")))


def ingest(es: Elastic, paths: list[Path], template_file: Path, index_prefix: str = "detlab") -> IngestReport:
    install_template(es, template_file)
    report = IngestReport()
    batches: dict[str, list[tuple[str | None, dict]]] = {}

    def flush(index: str) -> None:
        docs = batches.pop(index, [])
        report.errors.extend(es.bulk_index(index, docs))
        report.indexed[index] += len(docs)

    for file, record in normalize.iter_records(paths):
        try:
            source, doc = normalize.normalize(record)
        except normalize.UnknownRecordError as exc:
            report.skipped.append(f"{file.name}: {exc}")
            continue
        index = normalize.INDEX[source].replace("detlab", index_prefix, 1)
        batches.setdefault(index, []).append((normalize.document_id(source, record), doc))
        if len(batches[index]) >= BATCH:
            flush(index)
    for index in list(batches):
        flush(index)
    return report
