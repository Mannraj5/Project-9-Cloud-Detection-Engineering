"""A very small Elasticsearch HTTP client (standard library only).

Connection settings come from environment variables so that no secret is ever typed on the
command line or committed:

    ES_URL       e.g. http://localhost:9200 (default)
    ES_API_KEY   base64 API key (preferred), or
    ES_USERNAME / ES_PASSWORD
    ES_CA_CERT   path to the cluster's CA certificate when it uses HTTPS
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any


class ElasticError(RuntimeError):
    def __init__(self, status: int, body: str):
        super().__init__(f"Elasticsearch returned HTTP {status}: {body[:500]}")
        self.status = status
        self.body = body


class Elastic:
    def __init__(self, url: str | None = None, timeout: float = 60.0):
        self.url = (url or os.environ.get("ES_URL") or "http://localhost:9200").rstrip("/")
        self.timeout = timeout
        self.headers = {"Accept": "application/json"}
        api_key = os.environ.get("ES_API_KEY")
        user, password = os.environ.get("ES_USERNAME"), os.environ.get("ES_PASSWORD")
        if api_key:
            self.headers["Authorization"] = f"ApiKey {api_key}"
        elif user and password:
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"
        ca_cert = os.environ.get("ES_CA_CERT")
        self.context = ssl.create_default_context(cafile=ca_cert) if ca_cert else None

    def request(self, method: str, path: str, body: Any = None, ndjson: bool = False) -> Any:
        headers = dict(self.headers)
        data = None
        if body is not None:
            if ndjson:
                data = body.encode("utf-8")
                headers["Content-Type"] = "application/x-ndjson"
            else:
                data = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.context) as resp:
                text = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise ElasticError(exc.code, exc.read().decode("utf-8", "replace")) from None
        return json.loads(text) if text else None

    def put_index_template(self, name: str, template: dict[str, Any]) -> None:
        self.request("PUT", f"/_index_template/{name}", template)

    # Index create/delete changes cluster state, which a small node on a slow disk can take
    # longer than the default 30s to commit, so give those calls more time.
    _CLUSTER_TIMEOUT = "?master_timeout=2m&timeout=2m"

    def delete_index(self, index: str) -> None:
        try:
            self.request("DELETE", f"/{index}{self._CLUSTER_TIMEOUT}")
        except ElasticError as exc:
            if exc.status != 404:
                raise

    def create_index(self, index: str) -> None:
        self.request("PUT", f"/{index}{self._CLUSTER_TIMEOUT}")

    def clear_index(self, index: str) -> None:
        """Remove every document but keep the index (no cluster-state change)."""
        self.request("POST", f"/{index}/_delete_by_query?refresh=true&conflicts=proceed", {"query": {"match_all": {}}})

    def bulk_index(self, index: str, docs: list[tuple[str | None, dict[str, Any]]], refresh: bool = False) -> list[str]:
        """Index documents; returns a list of per-document error messages (empty if all good)."""
        if not docs:
            return []
        lines = []
        for doc_id, doc in docs:
            action: dict[str, Any] = {"index": {"_index": index}}
            if doc_id:
                action["index"]["_id"] = doc_id
            lines.append(json.dumps(action))
            lines.append(json.dumps(doc))
        path = "/_bulk" + ("?refresh=wait_for" if refresh else "")
        result = self.request("POST", path, "\n".join(lines) + "\n", ndjson=True)
        errors = []
        if result.get("errors"):
            for item in result["items"]:
                info = item.get("index", {})
                if "error" in info:
                    err = info["error"]
                    errors.append(f"{info.get('_id')}: {err.get('type')}: {err.get('reason')}")
        return errors

    def esql(self, query: str) -> dict[str, Any]:
        return self.request("POST", "/_query", {"query": query})
