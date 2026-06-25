"""
findings_server.py

MCP server for persisting and querying security findings in OpenSearch.
Provides a searchable, long-term store for findings across engagements,
with full-text search over tool output, CVE IDs, and findings text.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import mcp_error

server = Server("findings")

_OS_URL = os.environ.get("OPENSEARCH_URL", "http://odysseus-opensearch:9200").rstrip("/")
_OS_USER = os.environ.get("OPENSEARCH_USER", "admin")
_OS_PASS = os.environ.get("OPENSEARCH_PASSWORD", "admin")
_INDEX = "odysseus-findings"

_AUTH = HTTPBasicAuth(_OS_USER, _OS_PASS)
_HEADERS = {"Content-Type": "application/json"}
_TIMEOUT = 15


def _req(method: str, path: str, body: dict | None = None) -> dict:
    url = f"{_OS_URL}{path}"
    resp = requests.request(
        method, url,
        auth=_AUTH,
        headers=_HEADERS,
        json=body,
        timeout=_TIMEOUT,
        verify=False,  # self-signed cert common in dev; set OPENSEARCH_URL with https and real cert in prod
    )
    resp.raise_for_status()
    return resp.json()


def _ensure_index() -> str | None:
    """Create the findings index with mappings if it doesn't exist."""
    try:
        _req("HEAD", f"/{_INDEX}")
        return None
    except requests.HTTPError as e:
        if e.response.status_code != 404:
            return str(e)
    try:
        _req("PUT", f"/{_INDEX}", {
            "mappings": {
                "properties": {
                    "engagement": {"type": "keyword"},
                    "title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "severity": {"type": "keyword"},
                    "cvss": {"type": "float"},
                    "cve_id": {"type": "keyword"},
                    "ip": {"type": "ip"},
                    "port": {"type": "integer"},
                    "tool": {"type": "keyword"},
                    "description": {"type": "text"},
                    "evidence": {"type": "text", "index": False},
                    "status": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "created_at": {"type": "date"},
                    "updated_at": {"type": "date"},
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
            }
        })
        return None
    except Exception as exc:  # noqa: BLE001
        return str(exc)


TOOLS = [
    Tool(
        name="finding_index",
        description=(
            "Persist a security finding to the OpenSearch index for long-term search. "
            "Use this after each tool run to build a searchable findings corpus."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "engagement": {"type": "string", "description": "Engagement/project name for grouping"},
                "ip": {"type": "string", "description": "Target IP"},
                "port": {"type": "integer"},
                "cve_id": {"type": "string"},
                "cvss": {"type": "number"},
                "tool": {"type": "string"},
                "description": {"type": "string"},
                "evidence": {"type": "string", "description": "Raw tool output (not indexed for search)"},
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                },
                "status": {
                    "type": "string",
                    "enum": ["open", "remediated", "accepted", "false_positive"],
                    "default": "open",
                },
            },
            "required": ["title", "severity"],
        },
    ),
    Tool(
        name="finding_search",
        description=(
            "Full-text search across persisted findings in OpenSearch. "
            "Supports keyword search, severity filter, CVE lookup, and engagement scoping."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Full-text search query"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "engagement": {"type": "string"},
                "cve_id": {"type": "string"},
                "status": {"type": "string", "enum": ["open", "remediated", "accepted", "false_positive"]},
                "ip": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
            },
        },
    ),
    Tool(
        name="finding_stats",
        description="Return counts of findings broken down by severity and status across all engagements.",
        inputSchema={
            "type": "object",
            "properties": {
                "engagement": {"type": "string", "description": "Scope to a specific engagement (optional)"},
            },
        },
    ),
    Tool(
        name="finding_update_status",
        description="Update the status of a finding by its OpenSearch document ID.",
        inputSchema={
            "type": "object",
            "properties": {
                "doc_id": {"type": "string", "description": "OpenSearch document _id"},
                "status": {
                    "type": "string",
                    "enum": ["open", "remediated", "accepted", "false_positive"],
                },
                "notes": {"type": "string", "default": ""},
            },
            "required": ["doc_id", "status"],
        },
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:  # noqa: C901
    if err := _ensure_index():
        return [TextContent(type="text", text=mcp_error("opensearch_init", f"Index setup failed: {err}"))]

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        if name == "finding_index":
            doc = {
                "title": arguments["title"],
                "severity": arguments["severity"],
                "engagement": arguments.get("engagement", "default"),
                "ip": arguments.get("ip", ""),
                "port": arguments.get("port"),
                "cve_id": arguments.get("cve_id", ""),
                "cvss": arguments.get("cvss"),
                "tool": arguments.get("tool", ""),
                "description": arguments.get("description", ""),
                "evidence": arguments.get("evidence", ""),
                "tags": arguments.get("tags", []),
                "status": arguments.get("status", "open"),
                "created_at": now,
                "updated_at": now,
            }
            resp = _req("POST", f"/{_INDEX}/_doc", doc)
            result = f"Finding indexed. ID: {resp.get('_id', '?')}  Result: {resp.get('result', '?')}"

        elif name == "finding_search":
            must = []
            filter_clauses = []
            if q := arguments.get("query"):
                must.append({"multi_match": {"query": q, "fields": ["title", "description", "cve_id"]}})
            for field in ("severity", "engagement", "status"):
                if v := arguments.get(field):
                    filter_clauses.append({"term": {field: v}})
            if cve := arguments.get("cve_id"):
                filter_clauses.append({"term": {"cve_id": cve}})
            if ip := arguments.get("ip"):
                filter_clauses.append({"term": {"ip": ip}})
            body = {
                "query": {"bool": {"must": must or [{"match_all": {}}], "filter": filter_clauses}},
                "sort": [
                    {"severity": {"order": "asc"}},
                    {"created_at": {"order": "desc"}},
                ],
                "size": arguments.get("limit", 20),
                "_source": ["title", "severity", "cve_id", "ip", "tool", "status", "engagement", "created_at"],
            }
            resp = _req("POST", f"/{_INDEX}/_search", body)
            hits = resp.get("hits", {}).get("hits", [])
            total = resp.get("hits", {}).get("total", {}).get("value", 0)
            if not hits:
                result = "No findings matched."
            else:
                lines = [f"Total: {total} matching finding(s)  (showing {len(hits)})\n"]
                lines.append(f"{'ID':<26} {'Sev':<10} {'Status':<16} {'CVE':<18} {'IP':<16} {'Tool':<12} Title")
                lines.append("-" * 120)
                for h in hits:
                    s = h["_source"]
                    lines.append(
                        f"{h['_id']:<26} {s.get('severity',''):<10} {s.get('status',''):<16} "
                        f"{s.get('cve_id',''):<18} {s.get('ip',''):<16} {s.get('tool',''):<12} {s.get('title','')}"
                    )
                result = "\n".join(lines)

        elif name == "finding_stats":
            agg_filter = {}
            if eng := arguments.get("engagement"):
                agg_filter = {"filter": {"term": {"engagement": eng}}, "aggs": {
                    "by_severity": {"terms": {"field": "severity", "size": 5}},
                    "by_status": {"terms": {"field": "status", "size": 5}},
                }}
            body = {
                "size": 0,
                "aggs": agg_filter or {
                    "by_severity": {"terms": {"field": "severity", "size": 5}},
                    "by_status": {"terms": {"field": "status", "size": 5}},
                },
            }
            resp = _req("POST", f"/{_INDEX}/_search", body)
            aggs = resp.get("aggregations", {})
            if "filter" in aggs:
                aggs = aggs["filter"]
            sev_buckets = aggs.get("by_severity", {}).get("buckets", [])
            sta_buckets = aggs.get("by_status", {}).get("buckets", [])
            total = resp["hits"]["total"]["value"]
            lines = [f"Total indexed findings: {total}"]
            lines.append("By severity: " + "  ".join(f"{b['key']}:{b['doc_count']}" for b in sev_buckets))
            lines.append("By status:   " + "  ".join(f"{b['key']}:{b['doc_count']}" for b in sta_buckets))
            result = "\n".join(lines)

        elif name == "finding_update_status":
            doc_id = arguments["doc_id"]
            update = {"status": arguments["status"], "updated_at": now}
            if notes := arguments.get("notes"):
                update["notes"] = notes
            _req("POST", f"/{_INDEX}/_update/{doc_id}", {"doc": update})
            result = f"Finding {doc_id} updated to '{arguments['status']}'."

        else:
            result = mcp_error("unknown_tool", name)

    except requests.ConnectionError:
        result = mcp_error("opensearch_offline", "Cannot reach OpenSearch. Is the service running?")
    except requests.HTTPError as e:
        result = mcp_error("opensearch_http", f"HTTP {e.response.status_code}: {e.response.text[:200]}")
    except Exception as exc:  # noqa: BLE001
        result = mcp_error("opensearch_error", str(exc))

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
