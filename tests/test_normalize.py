import gzip
import json
from pathlib import Path

import pytest

from detlab import normalize


def test_cloudtrail_gets_timestamp_and_source() -> None:
    record = {"eventVersion": "1.10", "eventTime": "2026-12-01T00:00:00Z", "eventSource": "iam.amazonaws.com", "eventName": "ListUsers", "eventID": "abc"}
    source, doc = normalize.normalize(record)
    assert source == normalize.CLOUDTRAIL
    assert doc["@timestamp"] == "2026-12-01T00:00:00Z"
    assert doc["detlab"]["source"] == "cloudtrail"
    assert "detlab" not in record, "input must not be modified"
    assert normalize.document_id(source, record) == "abc"


def test_signin_upn_is_lower_cased() -> None:
    _, doc = normalize.normalize({"createdDateTime": "2026-12-01T00:00:00Z", "userPrincipalName": "BreakGlass01@Lab.Example"})
    assert doc["detlab"]["user_principal_name_lc"] == "breakglass01@lab.example"


def test_audit_modified_properties_are_flattened_and_unquoted() -> None:
    record = {
        "activityDisplayName": "Add member to role",
        "activityDateTime": "2026-12-01T00:00:00Z",
        "targetResources": [
            {"modifiedProperties": [
                {"displayName": "Role.DisplayName", "newValue": '"Global Administrator"'},
                {"displayName": "AccountEnabled", "newValue": "[false]"},
                {"displayName": "Plain", "newValue": "not json"},
            ]},
            {"modifiedProperties": [{"displayName": "Role.DisplayName", "newValue": '"Second"'}]},
        ],
    }
    _, doc = normalize.normalize(record)
    modified = doc["detlab"]["modified"]
    assert modified["Role_DisplayName"] == "Global Administrator"  # first value wins, stays single-valued
    assert modified["AccountEnabled"] == "[false]"
    assert modified["Plain"] == "not json"


def test_unknown_record_is_rejected() -> None:
    with pytest.raises(normalize.UnknownRecordError):
        normalize.normalize({"hello": "world"})


def test_iter_records_reads_cloudtrail_gzip_entra_array_and_skips_digest(tmp_path: Path) -> None:
    ct = tmp_path / "AWSLogs" / "111111111111" / "CloudTrail" / "ap-southeast-2"
    ct.mkdir(parents=True)
    (ct / "events.json.gz").write_bytes(gzip.compress(json.dumps({"Records": [{"eventID": "1"}, {"eventID": "2"}]}).encode()))
    digest = tmp_path / "AWSLogs" / "111111111111" / "CloudTrail-Digest"
    digest.mkdir(parents=True)
    (digest / "d.json.gz").write_bytes(gzip.compress(b'{"digestPublicKeyFingerprint": "x"}'))
    (tmp_path / "signins.json").write_text(json.dumps([{"id": "a"}, {"id": "b"}, {"id": "c"}]), encoding="utf-8")
    (tmp_path / "graph.json").write_text(json.dumps({"value": [{"id": "g"}]}), encoding="utf-8")
    (tmp_path / "lines.jsonl").write_text('{"id": "l1"}\n{"id": "l2"}\n', encoding="utf-8")

    records = [r for _, r in normalize.iter_records([tmp_path])]
    ids = sorted(r.get("eventID") or r.get("id") for r in records)
    assert ids == ["1", "2", "a", "b", "c", "g", "l1", "l2"]
