"""
spiderfoot_server.py

MCP server wrapping the SpiderFoot OSINT automation platform.
SpiderFoot runs as a sidecar container (odysseus-spiderfoot) exposing a REST API
on port 5001. This server handles the full async scan lifecycle:
  start → poll status → retrieve structured JSON results.

Use cases:
  passive    — passive only, no active probing (safe for external targets)
  investigate — balanced passive + active (default)
  footprint  — full attack surface mapping
  all        — every module, most thorough / most noisy
"""

import asyncio
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

server = Server("spiderfoot")

_SF_BASE_URL = os.environ.get("SPIDERFOOT_URL", "http://odysseus-spiderfoot:5001")
_SF_USER = os.environ.get("SPIDERFOOT_USERNAME", "")
_SF_PASS = os.environ.get("SPIDERFOOT_PASSWORD", "")
_REQUEST_TIMEOUT = int(os.environ.get("SPIDERFOOT_REQUEST_TIMEOUT", "30"))
_POLL_INTERVAL = int(os.environ.get("SPIDERFOOT_POLL_INTERVAL", "10"))

_AUTH: tuple[str, str] | None = (_SF_USER, _SF_PASS) if _SF_USER else None

TOOLS = [
    Tool(
        name="sf_scan_start",
        description=(
            "Start a SpiderFoot OSINT scan against a target and return a scan ID immediately. "
            "Use sf_scan_status to poll progress and sf_scan_results to retrieve findings. "
            "Authorized targets only."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Domain, IP, email address, username, or subnet",
                },
                "scan_name": {
                    "type": "string",
                    "description": "Human-readable label for this scan",
                    "default": "chiron scan",
                },
                "usecase": {
                    "type": "string",
                    "enum": ["passive", "investigate", "footprint", "all"],
                    "description": "Scan intensity preset (passive = no active probing)",
                    "default": "passive",
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="sf_scan_status",
        description="Check the status of a running or completed SpiderFoot scan.",
        inputSchema={
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Scan ID returned by sf_scan_start"},
            },
            "required": ["scan_id"],
        },
    ),
    Tool(
        name="sf_scan_results",
        description=(
            "Retrieve structured JSON results from a completed SpiderFoot scan. "
            "Optionally filter to specific event types (e.g. EMAILADDR, IP_ADDRESS, VULNERABILITY_CVE_CRITICAL)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "scan_id": {"type": "string"},
                "event_type": {
                    "type": "string",
                    "description": (
                        "Filter by SpiderFoot event type. Leave empty for all results. "
                        "Common types: EMAILADDR, DOMAIN_NAME, IP_ADDRESS, PHONE_NUMBER, "
                        "VULNERABILITY_CVE_CRITICAL, VULNERABILITY_CVE_HIGH, LINKED_URL_INTERNAL, "
                        "INTERNET_NAME, SOCIAL_MEDIA, DATA_BREACH"
                    ),
                    "default": "",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results to return (0 = all)",
                    "default": 100,
                },
            },
            "required": ["scan_id"],
        },
    ),
    Tool(
        name="sf_quick_scan",
        description=(
            "Convenience: start a passive SpiderFoot scan, wait for it to complete, "
            "and return a summarised result set. Blocks for up to `timeout` seconds. "
            "For long or active scans use sf_scan_start + sf_scan_status + sf_scan_results instead."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "usecase": {
                    "type": "string",
                    "enum": ["passive", "investigate"],
                    "default": "passive",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max seconds to wait (default 300 / 5 min)",
                    "default": 300,
                },
                "event_type": {
                    "type": "string",
                    "description": "Optional event type filter for returned results",
                    "default": "",
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="sf_list_scans",
        description="List all SpiderFoot scans with their IDs, targets, statuses, and result counts.",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="sf_module_list",
        description="List all available SpiderFoot modules with their categories and descriptions.",
        inputSchema={
            "type": "object",
            "properties": {
                "filter_category": {
                    "type": "string",
                    "description": "Optional category filter (e.g. 'Passive DNS', 'Social Media')",
                    "default": "",
                }
            },
        },
    ),
]


# ---------------------------------------------------------------------------
# Internal HTTP helpers
# ---------------------------------------------------------------------------

def _url(path: str) -> str:
    return urljoin(_SF_BASE_URL, path)


def _get(path: str, params: dict | None = None) -> dict | list | str:
    try:
        resp = requests.get(
            _url(path),
            params=params or {},
            auth=_AUTH,
            timeout=_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.ConnectionError:
        return {"error": f"Cannot reach SpiderFoot at {_SF_BASE_URL}. Is odysseus-spiderfoot running?"}
    except requests.HTTPError as exc:
        return {"error": f"HTTP {exc.response.status_code}: {exc.response.text[:300]}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _post(path: str, data: dict) -> dict | str:
    try:
        resp = requests.post(
            _url(path),
            data=data,
            auth=_AUTH,
            timeout=_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        ct = resp.headers.get("content-type", "")
        return resp.json() if "json" in ct else resp.text
    except requests.ConnectionError:
        return {"error": f"Cannot reach SpiderFoot at {_SF_BASE_URL}. Is odysseus-spiderfoot running?"}
    except requests.HTTPError as exc:
        return {"error": f"HTTP {exc.response.status_code}: {exc.response.text[:300]}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# SpiderFoot API operations
# ---------------------------------------------------------------------------

def _find_scan_id_by_name(scan_name: str) -> str | None:
    """Look up a just-started scan's real ID from /scanlist by its scanname
    -- the fallback used when /startscan's own response doesn't carry the
    ID directly (see _start_scan). Each row is
    [scan_id, name, target, created, started, finished, status, count];
    scan_name is unique enough for this script's own timestamped names,
    and /scanlist is newest-first, so the first match is the right one."""
    rows = _get("/scanlist")
    if isinstance(rows, list):
        for row in rows:
            if len(row) > 1 and row[1] == scan_name:
                return row[0]
    return None


def _start_scan(target: str, scan_name: str, usecase: str) -> dict:
    result = _post("/startscan", {
        "scanname": scan_name,
        "scantarget": target,
        "usecase": usecase,
        # SpiderFoot's /startscan 404s with "Missing parameters:
        # typelist,modulelist" unless both are present, even empty --
        # `usecase` alone (e.g. "passive"/"footprint"/"investigate")
        # is how SpiderFoot itself picks the actual module set when
        # these are blank, so leaving them "" preserves that behavior.
        "typelist": "",
        "modulelist": "",
    })
    if isinstance(result, dict) and "error" in result:
        return result  # propagate error dict
    scan_id = None
    if isinstance(result, str):
        text = result.strip()
        # Some SpiderFoot builds return the scan ID as a short plain
        # string on success; others (confirmed on v2.12) render the full
        # scan-list HTML page instead and carry no ID in the response body
        # at all -- in that case fall back to looking it up by name.
        if text and "<" not in text and len(text) < 64:
            scan_id = text
    elif isinstance(result, dict):
        scan_id = result.get("id") or result.get("scan_id")
    if not scan_id:
        scan_id = _find_scan_id_by_name(scan_name)
    if not scan_id:
        return {"error": f"Scan '{scan_name}' was started but its ID could not be determined from /scanlist."}
    return {"scan_id": scan_id}


def _get_status(scan_id: str) -> dict:
    data = _get(f"/scanstatus/{scan_id}")
    if isinstance(data, list) and data:
        # /scanstatus/<id> returns ONE flat row directly -- confirmed live:
        # [name, target, created, started, ended, status] -- unlike
        # /scanlist, which returns a *list* of such rows (with an extra
        # leading scan_id and trailing result_count). Indexing data[0]
        # here silently picked off the scan's *name string* and then
        # indexed into individual characters of it -- status ended up
        # being some character of the name, which could never equal
        # "FINISHED"/"ABORTED"/"ERROR-FAILED", so _wait_for_scan polled
        # forever no matter how fast the scan actually finished.
        row = data
        return {
            "scan_id": scan_id,
            "name": row[0] if len(row) > 0 else "",
            "target": row[1] if len(row) > 1 else "",
            "created": row[2] if len(row) > 2 else "",
            "started": row[3] if len(row) > 3 else "",
            "ended": row[4] if len(row) > 4 else "",
            "status": row[5] if len(row) > 5 else "UNKNOWN",
        }
    if isinstance(data, dict):
        return data
    return {"status": "UNKNOWN", "raw": str(data)}


def _get_results(scan_id: str, event_type: str = "", limit: int = 100) -> list[dict]:
    # /scaneventresults takes id/eventType as QUERY params, not path
    # segments (confirmed against SpiderFoot's own sfwebui.py) -- it
    # requires eventType to be present at all (SpiderFoot's convention for
    # "no filter" is the literal string "ALL", not an omitted/empty param).
    data = _get("/scaneventresults", params={"id": scan_id, "eventType": event_type or "ALL"})
    if not isinstance(data, list):
        return [{"error": str(data)}]
    rows = data
    if limit > 0:
        rows = rows[:limit]
    # Row shape per sfwebui.py's scaneventresults(): [lastseen, data,
    # source, module, confidence, visibility, risk, hash, ?, ?, type] --
    # type is the LAST element, not the first.
    parsed = []
    for row in rows:
        if not isinstance(row, list) or len(row) < 11:
            continue
        parsed.append({
            "type": row[10],
            "module": row[3],
            "source": row[2],
            "data": row[1],
        })
    return parsed


def _list_scans() -> list[dict]:
    data = _get("/scanlist")
    if not isinstance(data, list):
        return [{"error": str(data)}]
    scans = []
    for row in data:
        if not isinstance(row, list) or len(row) < 6:
            continue
        scans.append({
            "scan_id": row[0],
            "name": row[1],
            "target": row[2],
            "started": row[3],
            "ended": row[4],
            "status": row[5],
            "result_count": row[6] if len(row) > 6 else "?",
        })
    return scans


def _format_results(results: list[dict], limit: int = 100) -> str:
    if not results:
        return "No results found."
    if results and "error" in results[0]:
        return f"[error] {results[0]['error']}"
    # Group by event type for readability
    by_type: dict[str, list[str]] = {}
    for r in results:
        t = r.get("type", "UNKNOWN")
        by_type.setdefault(t, []).append(r.get("data", ""))
    lines = [f"Total findings: {len(results)}", ""]
    for event_type, entries in sorted(by_type.items()):
        lines.append(f"[{event_type}] ({len(entries)})")
        for entry in entries[:20]:  # cap per-type display
            lines.append(f"  {entry}")
        if len(entries) > 20:
            lines.append(f"  ... and {len(entries) - 20} more")
        lines.append("")
    return "\n".join(lines)


def _wait_for_scan(scan_id: str, timeout: int) -> dict:
    """Poll until scan finishes or timeout. Returns final status dict."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = _get_status(scan_id)
        state = status.get("status", "UNKNOWN")
        if state in ("FINISHED", "ABORTED", "ERROR-FAILED"):
            return status
        if "error" in status:
            return status
        time.sleep(_POLL_INTERVAL)
    return {"status": "TIMEOUT", "scan_id": scan_id, "message": f"Scan did not finish within {timeout}s. Use sf_scan_status to continue monitoring."}


# ---------------------------------------------------------------------------
# MCP handlers
# ---------------------------------------------------------------------------

@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "sf_scan_start":
        result = _start_scan(
            target=arguments["target"],
            scan_name=arguments.get("scan_name", "chiron scan"),
            usecase=arguments.get("usecase", "passive"),
        )
        if "error" in result:
            text = f"[error] {result['error']}"
        else:
            scan_id = result.get("scan_id", "unknown")
            text = (
                f"Scan started. ID: {scan_id}\n"
                f"Target: {arguments['target']}  Use case: {arguments.get('usecase', 'passive')}\n"
                f"Poll with: sf_scan_status(scan_id='{scan_id}')\n"
                f"Results via: sf_scan_results(scan_id='{scan_id}')"
            )

    elif name == "sf_scan_status":
        status = _get_status(arguments["scan_id"])
        if "error" in status:
            text = f"[error] {status['error']}"
        else:
            text = "\n".join(f"{k}: {v}" for k, v in status.items())

    elif name == "sf_scan_results":
        results = _get_results(
            scan_id=arguments["scan_id"],
            event_type=arguments.get("event_type", ""),
            limit=int(arguments.get("limit", 100)),
        )
        text = _format_results(results, limit=int(arguments.get("limit", 100)))

    elif name == "sf_quick_scan":
        target = arguments["target"]
        usecase = arguments.get("usecase", "passive")
        timeout = int(arguments.get("timeout", 300))
        event_type = arguments.get("event_type", "")

        start_result = _start_scan(target=target, scan_name=f"quick: {target}", usecase=usecase)
        if "error" in start_result:
            text = f"[error starting scan] {start_result['error']}"
        else:
            scan_id = start_result["scan_id"]
            final_status = _wait_for_scan(scan_id, timeout)
            state = final_status.get("status", "UNKNOWN")

            if state == "TIMEOUT":
                text = (
                    f"Scan started but did not complete within {timeout}s.\n"
                    f"Scan ID: {scan_id}\n"
                    f"Continue monitoring with sf_scan_status(scan_id='{scan_id}')"
                )
            elif state in ("ABORTED", "ERROR-FAILED"):
                text = f"Scan {state}. ID: {scan_id}"
            else:
                results = _get_results(scan_id=scan_id, event_type=event_type, limit=100)
                text = f"Scan complete [{state}] — ID: {scan_id}\n\n" + _format_results(results)

    elif name == "sf_list_scans":
        scans = _list_scans()
        if not scans:
            text = "No scans found."
        elif "error" in scans[0]:
            text = f"[error] {scans[0]['error']}"
        else:
            lines = [f"{'ID':<36}  {'Status':<16}  {'Target':<30}  Results"]
            lines.append("-" * 90)
            for s in scans:
                lines.append(
                    f"{s['scan_id']:<36}  {s['status']:<16}  {s['target']:<30}  {s['result_count']}"
                )
            text = "\n".join(lines)

    elif name == "sf_module_list":
        data = _get("/modulelist")
        if isinstance(data, dict) and "error" in data:
            text = f"[error] {data['error']}"
        elif isinstance(data, list):
            filter_cat = arguments.get("filter_category", "").lower()
            lines = []
            for module in data:
                if not isinstance(module, dict):
                    continue
                cat = module.get("cats", [""])[0] if module.get("cats") else ""
                if filter_cat and filter_cat not in cat.lower():
                    continue
                lines.append(f"[{cat}] {module.get('name', '?')} — {module.get('descr', '')[:80]}")
            text = "\n".join(lines) if lines else "No modules matched."
        else:
            text = str(data)

    else:
        text = f"[error] Unknown tool: {name}"

    return [TextContent(type="text", text=text)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
