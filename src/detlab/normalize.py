"""Read raw log files and normalise records before they reach Elasticsearch.

The same normalise() runs at ingest time and in the offline tests, so a rule that passes its
tests sees exactly the documents it will see in the SIEM.

Normalisation keeps every original field and only adds:

* ``@timestamp``: copied from the source's own time field.
* ``detlab.source``: cloudtrail, entra_signin or entra_audit.
* ``detlab.user_principal_name_lc``: lower-cased UPN for Entra sign-ins. ES|QL string
  comparisons are case-sensitive, and UPNs are not reliably lower case.
* ``detlab.modified.<Name>``: Entra audit ``targetResources[].modifiedProperties[]``
  flattened to single values. ES|QL returns null for comparisons on multi-valued fields, so
  a rule cannot match inside the original nested array.
"""

from __future__ import annotations

import copy
import gzip
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

CLOUDTRAIL = "cloudtrail"
ENTRA_SIGNIN = "entra_signin"
ENTRA_AUDIT = "entra_audit"

INDEX = {
    CLOUDTRAIL: "detlab-cloudtrail",
    ENTRA_SIGNIN: "detlab-entra-signin",
    ENTRA_AUDIT: "detlab-entra-audit",
}

TIME_FIELD = {
    CLOUDTRAIL: "eventTime",
    ENTRA_SIGNIN: "createdDateTime",
    ENTRA_AUDIT: "activityDateTime",
}

ID_FIELD = {
    CLOUDTRAIL: "eventID",
    ENTRA_SIGNIN: "id",
    ENTRA_AUDIT: "id",
}


class UnknownRecordError(ValueError):
    """Raised when a record does not look like CloudTrail, an Entra sign-in or an Entra audit event."""


def detect_source(record: dict[str, Any]) -> str:
    if "eventSource" in record and "eventName" in record and "eventTime" in record:
        return CLOUDTRAIL
    if "activityDisplayName" in record and "activityDateTime" in record:
        return ENTRA_AUDIT
    if "createdDateTime" in record and "userPrincipalName" in record:
        return ENTRA_SIGNIN
    raise UnknownRecordError(
        "record is not CloudTrail, an Entra sign-in or an Entra audit event; "
        f"top-level keys: {sorted(record)[:12]}"
    )


def _unquote(value: Any) -> Any:
    """Entra stores modifiedProperties values as JSON text, e.g. '"Global Administrator"'."""
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return text
    try:
        parsed = json.loads(text)
    except ValueError:
        return value
    if isinstance(parsed, str):
        return parsed
    if isinstance(parsed, list) and len(parsed) == 1 and isinstance(parsed[0], str):
        return parsed[0]
    return value


def _flatten_modified_properties(record: dict[str, Any]) -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for target in record.get("targetResources") or []:
        if not isinstance(target, dict):
            continue
        for prop in target.get("modifiedProperties") or []:
            if not isinstance(prop, dict) or not prop.get("displayName"):
                continue
            key = str(prop["displayName"]).replace(".", "_")
            # First value wins so the field stays single-valued; see docs/design-notes.md.
            flat.setdefault(key, _unquote(prop.get("newValue")))
    return flat


def normalize(record: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Return (source, document). The input record is not modified."""
    source = detect_source(record)
    doc = copy.deepcopy(record)
    detlab: dict[str, Any] = {"source": source}

    timestamp = record.get(TIME_FIELD[source])
    if timestamp:
        doc["@timestamp"] = timestamp

    if source == ENTRA_SIGNIN and isinstance(record.get("userPrincipalName"), str):
        detlab["user_principal_name_lc"] = record["userPrincipalName"].lower()

    if source == ENTRA_AUDIT:
        modified = _flatten_modified_properties(record)
        if modified:
            detlab["modified"] = modified

    doc["detlab"] = detlab
    return source, doc


def document_id(source: str, record: dict[str, Any]) -> str | None:
    """Stable ID so that ingesting the same file twice does not create duplicates."""
    value = record.get(ID_FIELD[source])
    return str(value) if value else None


def _load_json_text(text: str) -> list[dict[str, Any]]:
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        # JSON Lines: one object per line.
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("Records"), list):  # CloudTrail S3 object
            return data["Records"]
        if isinstance(data.get("value"), list):  # Microsoft Graph page
            return data["value"]
        return [data]
    raise ValueError("unsupported JSON layout")


def iter_files(paths: list[Path]) -> Iterator[Path]:
    for path in paths:
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.name.endswith((".json", ".json.gz", ".jsonl")):
                    yield child
        else:
            yield path


def iter_records(paths: list[Path]) -> Iterator[tuple[Path, dict[str, Any]]]:
    """Yield (file, record) for every record in the given files or folders.

    Handles CloudTrail S3 objects (.json.gz with a Records array), Entra portal JSON
    exports (a JSON array), Graph API pages ({"value": [...]}) and JSON Lines.
    CloudTrail digest files are skipped because they hold hashes, not events.
    """
    for file in iter_files(paths):
        if "CloudTrail-Digest" in file.as_posix():
            continue
        raw = file.read_bytes()
        if file.name.endswith(".gz"):
            raw = gzip.decompress(raw)
        for record in _load_json_text(raw.decode("utf-8-sig")):
            yield file, record
