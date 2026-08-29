"""
sigma_server.py

MCP server for authoring and testing Sigma detection rules -- the
log-detection complement to yara_server.py's file-pattern detection. Rules
are stored as YAML files under $ODYSSEUS_DATA_DIR/sigma_rules (host-side,
not the Kali sidecar -- Sigma rule parsing/conversion is pure Python and
matches against log/finding data already sitting in OpenSearch, not files
on a target host, so there's no analog to yara_scan's "scan this file").

Conversion and live testing need the optional `pysigma` +
`pysigma-backend-opensearch` packages (see requirements-optional.txt).
Without them, sigma_rule_write/list/delete still work (a rule is valid
YAML); sigma_rule_convert/sigma_rule_test return a clear "not_installed"
error instead of crashing server registration -- same gated-import pattern
as pdf_server.py's _FPDF_AVAILABLE/_PYPDF_AVAILABLE.

Rules are matched against mcp_servers/findings_server.py's `odysseus-findings`
OpenSearch index by default -- write detection logic against that index's
fields (title, severity, cvss, cve_id, ip, port, tool, description, status,
tags), not raw Sysmon/Windows event fields, unless you're pointing
sigma_rule_test at a different index that has those.
"""

import asyncio
import os
import re
import sys
from pathlib import Path

import requests
import yaml
from requests.auth import HTTPBasicAuth

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import mcp_error

server = Server("sigma")

_DATA_DIR = Path(os.environ.get("ODYSSEUS_DATA_DIR", "./data"))
_RULES_DIR = _DATA_DIR / "sigma_rules"

# Duplicated from findings_server.py rather than imported -- MCP servers in
# this fork are standalone subprocesses and never import each other.
_OS_URL = os.environ.get("OPENSEARCH_URL", "http://odysseus-opensearch:9200").rstrip("/")
_OS_USER = os.environ.get("OPENSEARCH_USER", "admin")
_OS_PASS = os.environ.get("OPENSEARCH_PASSWORD", "admin")
_AUTH = HTTPBasicAuth(_OS_USER, _OS_PASS)
_DEFAULT_INDEX = "odysseus-findings"

_RULE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.opensearch import OpensearchLuceneBackend
    _PYSIGMA_AVAILABLE = True
except ImportError:
    _PYSIGMA_AVAILABLE = False


def _rule_path(name: str) -> Path | None:
    """Return the on-disk path for a rule name, or None if the name fails
    validation (path traversal, absolute paths, anything but
    alnum/underscore/hyphen)."""
    if not _RULE_NAME_RE.match(name):
        return None
    return _RULES_DIR / f"{name}.yml"


def _list_rules() -> list[str]:
    """Stored rule names, for direct import by the security dashboard's
    rule-management route (and reused by the sigma_rule_list tool below so
    there's one source of truth for what "stored rules" means)."""
    _RULES_DIR.mkdir(parents=True, exist_ok=True)
    return sorted(p.stem for p in _RULES_DIR.glob("*.yml"))


def _read_rule(name: str) -> tuple[str | None, str | None]:
    """Load a stored rule's raw YAML. Returns (content, error)."""
    path = _rule_path(name)
    if path is None:
        return None, mcp_error("invalid_name", f"{name!r} must be alnum/underscore/hyphen only")
    if not path.exists():
        return None, mcp_error("not_found", f"No stored rule named {name!r}")
    return path.read_text(encoding="utf-8"), None


def _os_search(index: str, query_string: str, limit: int) -> dict:
    try:
        resp = requests.post(
            f"{_OS_URL}/{index}/_search",
            auth=_AUTH,
            json={"query": {"query_string": {"query": query_string}}, "size": limit},
            timeout=15,
            verify=False,  # nosec B501 -- self-signed cert common in dev; same accepted risk as findings_server.py's _req(); set OPENSEARCH_URL with https and a real cert in prod
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:  # noqa: BLE001
        return {"_mcp_error": str(exc)}


TOOLS = [
    Tool(
        name="sigma_rule_write",
        description="Save a Sigma detection rule (YAML) to the rule store, validating that it parses as a well-formed Sigma rule.",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Rule filename, alnum/underscore/hyphen only, no extension"},
                "rule_yaml": {"type": "string", "description": "Full Sigma rule YAML (title, logsource, detection, level, tags)"},
            },
            "required": ["name", "rule_yaml"],
        },
    ),
    Tool(
        name="sigma_rule_list",
        description="List stored Sigma rules.",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="sigma_rule_delete",
        description="Delete a stored Sigma rule.",
        inputSchema={
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    ),
    Tool(
        name="sigma_rule_convert",
        description="Convert a stored Sigma rule to an OpenSearch Lucene query string, without running it.",
        inputSchema={
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    ),
    Tool(
        name="sigma_rule_test",
        description="Convert a stored Sigma rule and run it against an OpenSearch index (default: odysseus-findings), returning match count and sample hits.",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "index": {"type": "string", "default": _DEFAULT_INDEX},
                "limit": {"type": "integer", "default": 20},
            },
            "required": ["name"],
        },
    ),
]


def _convert_rule(name: str) -> tuple[list[str] | None, str | None]:
    """Load + convert a stored rule. Returns (queries, error)."""
    if not _PYSIGMA_AVAILABLE:
        return None, mcp_error("not_installed", "pysigma / pysigma-backend-opensearch not installed — see requirements-optional.txt")
    path = _rule_path(name)
    if path is None:
        return None, mcp_error("invalid_name", f"{name!r} must be alnum/underscore/hyphen only")
    if not path.exists():
        return None, mcp_error("not_found", f"No stored rule named {name!r}")
    try:
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        queries = OpensearchLuceneBackend().convert(collection)
        return queries, None
    except Exception as exc:  # noqa: BLE001
        return None, mcp_error("convert_error", str(exc))


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:  # noqa: C901
    try:
        if name == "sigma_rule_write":
            rule_name = arguments["name"]
            path = _rule_path(rule_name)
            if path is None:
                result = mcp_error("invalid_name", f"{rule_name!r} must be alnum/underscore/hyphen only")
            else:
                try:
                    if _PYSIGMA_AVAILABLE:
                        # Full validation: well-formed Sigma (title, logsource,
                        # detection), not just syntactically valid YAML.
                        SigmaCollection.from_yaml(arguments["rule_yaml"])
                    else:
                        # Degraded validation without the optional dep: at
                        # least confirm it parses as YAML at all.
                        yaml.safe_load(arguments["rule_yaml"])
                except Exception as exc:  # noqa: BLE001
                    result = mcp_error("invalid_rule", str(exc))
                else:
                    _RULES_DIR.mkdir(parents=True, exist_ok=True)
                    path.write_text(arguments["rule_yaml"], encoding="utf-8")
                    result = f"Rule {rule_name!r} saved."
                    if not _PYSIGMA_AVAILABLE:
                        result += " (pysigma not installed — only YAML syntax was checked, not Sigma rule structure; convert/test are unavailable until it's installed)"

        elif name == "sigma_rule_list":
            rules = _list_rules()
            result = "\n".join(rules) if rules else "No stored rules."

        elif name == "sigma_rule_delete":
            path = _rule_path(arguments["name"])
            if path is None:
                result = mcp_error("invalid_name", f"{arguments['name']!r} must be alnum/underscore/hyphen only")
            elif not path.exists():
                result = mcp_error("not_found", f"No stored rule named {arguments['name']!r}")
            else:
                path.unlink()
                result = f"Rule {arguments['name']!r} deleted."

        elif name == "sigma_rule_convert":
            queries, err = _convert_rule(arguments["name"])
            result = err or "\n".join(queries)

        elif name == "sigma_rule_test":
            queries, err = _convert_rule(arguments["name"])
            if err:
                result = err
            else:
                index = arguments.get("index", _DEFAULT_INDEX)
                limit = int(arguments.get("limit", 20))
                lines = []
                for q in queries:
                    data = _os_search(index, q, limit)
                    if "_mcp_error" in data:
                        lines.append(f"Query {q!r} failed: {data['_mcp_error']}")
                        continue
                    hits = data.get("hits", {})
                    total = hits.get("total", {})
                    total_count = total.get("value", total) if isinstance(total, dict) else total
                    lines.append(f"Query: {q}\nMatches: {total_count}")
                    for h in hits.get("hits", [])[:limit]:
                        src = h.get("_source", {})
                        lines.append(f"  - {src.get('title', h.get('_id'))} ({src.get('severity', '?')})")
                result = "\n".join(lines)

        else:
            result = mcp_error("unknown_tool", name)

    except Exception as exc:  # noqa: BLE001
        result = mcp_error("error", str(exc))

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
