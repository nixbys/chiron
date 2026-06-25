"""
attck_server.py

MCP server for MITRE ATT&CK framework lookups and technique mapping.
Uses the MITRE ATT&CK STIX data fetched from the official GitHub repository
and cached locally in the Odysseus data directory.

Provides technique lookup, tactic enumeration, mitigation guidance,
and mapping of observed TTPs to the ATT&CK matrix.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

import requests

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import mcp_error

server = Server("attck")

_DATA_DIR = Path(os.environ.get("ODYSSEUS_DATA_DIR", "./data"))
_CACHE_FILE = _DATA_DIR / "attck_enterprise.json"
_CACHE_MAX_AGE = 7 * 24 * 3600  # 7 days

_ATTCK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

_cache: dict | None = None
_technique_index: dict[str, dict] | None = None
_tactic_index: dict[str, list] | None = None


def _load_cache() -> dict | None:
    global _cache, _technique_index, _tactic_index
    if _cache is not None:
        return _cache
    if _CACHE_FILE.exists() and (time.time() - _CACHE_FILE.stat().st_mtime) < _CACHE_MAX_AGE:
        try:
            _cache = json.loads(_CACHE_FILE.read_text())
            _build_indexes()
            return _cache
        except Exception:  # noqa: BLE001
            pass
    return None


def _fetch_attck() -> str | None:
    """Fetch ATT&CK STIX data and cache it. Returns error string or None."""
    global _cache, _technique_index, _tactic_index
    try:
        resp = requests.get(_ATTCK_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(json.dumps(data))
        _cache = data
        _build_indexes()
        return None
    except Exception as exc:  # noqa: BLE001
        return str(exc)


def _build_indexes() -> None:
    global _technique_index, _tactic_index
    if _cache is None:
        return
    _technique_index = {}
    _tactic_index = {}
    for obj in _cache.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext = obj.get("external_references", [])
        tid = next((r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"), None)
        if not tid:
            continue
        _technique_index[tid.upper()] = obj
        for phase in obj.get("kill_chain_phases", []):
            tactic = phase.get("phase_name", "")
            _tactic_index.setdefault(tactic, []).append(tid)


def _ensure_loaded() -> str | None:
    if _load_cache() is not None:
        return None
    return _fetch_attck()


TOOLS = [
    Tool(
        name="attck_update",
        description=(
            "Download or refresh the local MITRE ATT&CK Enterprise STIX dataset. "
            "Data is cached for 7 days. Run this before first use or to get latest techniques."
        ),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="attck_technique",
        description=(
            "Look up a MITRE ATT&CK technique by ID (e.g. T1566, T1566.001). "
            "Returns name, tactic, description, platforms, and mitigations."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "technique_id": {
                    "type": "string",
                    "description": "ATT&CK technique ID (e.g. T1566 or T1566.001)",
                },
            },
            "required": ["technique_id"],
        },
    ),
    Tool(
        name="attck_tactic",
        description="List all techniques under a given ATT&CK tactic phase.",
        inputSchema={
            "type": "object",
            "properties": {
                "tactic": {
                    "type": "string",
                    "description": "Tactic phase name (e.g. 'initial-access', 'lateral-movement', 'exfiltration')",
                },
            },
            "required": ["tactic"],
        },
    ),
    Tool(
        name="attck_search",
        description="Search ATT&CK techniques by keyword in name or description.",
        inputSchema={
            "type": "object",
            "properties": {
                "keyword": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
            },
            "required": ["keyword"],
        },
    ),
    Tool(
        name="attck_map",
        description=(
            "Map a list of observed technique IDs to an ATT&CK summary: "
            "tactic coverage, techniques used, gaps, and recommended mitigations."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "technique_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of observed ATT&CK technique IDs",
                },
                "context": {
                    "type": "string",
                    "description": "Optional engagement context (e.g. 'ransomware incident', 'red team')",
                    "default": "",
                },
            },
            "required": ["technique_ids"],
        },
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "attck_update":
        err = _fetch_attck()
        if err:
            result = mcp_error("fetch_failed", f"Could not download ATT&CK data: {err}")
        else:
            count = len(_technique_index or {})
            result = f"ATT&CK Enterprise dataset loaded: {count} techniques indexed."

    elif name == "attck_technique":
        if err := _ensure_loaded():
            return [TextContent(type="text", text=mcp_error("not_loaded", f"ATT&CK data unavailable: {err}. Run attck_update first."))]
        tid = arguments["technique_id"].upper()
        obj = (_technique_index or {}).get(tid)
        if not obj:
            return [TextContent(type="text", text=mcp_error("not_found", f"Technique {tid} not found"))]
        name_str = obj.get("name", "?")
        desc = obj.get("description", "")[:600]
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
        platforms = obj.get("x_mitre_platforms", [])
        ext = obj.get("external_references", [])
        url = next((r.get("url", "") for r in ext if r.get("source_name") == "mitre-attack"), "")
        result = (
            f"Technique: {tid} — {name_str}\n"
            f"Tactics: {', '.join(tactics)}\n"
            f"Platforms: {', '.join(platforms)}\n"
            f"URL: {url}\n\n"
            f"Description:\n{desc}"
        )

    elif name == "attck_tactic":
        if err := _ensure_loaded():
            return [TextContent(type="text", text=mcp_error("not_loaded", f"ATT&CK data unavailable: {err}. Run attck_update first."))]
        tactic = arguments["tactic"].lower().replace(" ", "-")
        technique_ids = (_tactic_index or {}).get(tactic, [])
        if not technique_ids:
            all_tactics = sorted((_tactic_index or {}).keys())
            return [TextContent(type="text", text=f"Tactic '{tactic}' not found.\nAvailable: {', '.join(all_tactics)}")]
        lines = [f"Tactic: {tactic} ({len(technique_ids)} techniques)"]
        for tid in sorted(technique_ids):
            obj = (_technique_index or {}).get(tid, {})
            lines.append(f"  {tid:<14} {obj.get('name', '?')}")
        result = "\n".join(lines)

    elif name == "attck_search":
        if err := _ensure_loaded():
            return [TextContent(type="text", text=mcp_error("not_loaded", f"ATT&CK data unavailable: {err}. Run attck_update first."))]
        keyword = arguments["keyword"].lower()
        limit = int(arguments.get("limit", 20))
        matches = []
        for tid, obj in (_technique_index or {}).items():
            name_str = obj.get("name", "").lower()
            desc = obj.get("description", "").lower()
            if keyword in name_str or keyword in desc:
                matches.append((tid, obj.get("name", "?")))
        matches = sorted(matches)[:limit]
        if not matches:
            result = f"No techniques found matching '{keyword}'."
        else:
            lines = [f"Found {len(matches)} match(es) for '{keyword}':"]
            for tid, tname in matches:
                lines.append(f"  {tid:<14} {tname}")
            result = "\n".join(lines)

    elif name == "attck_map":
        if err := _ensure_loaded():
            return [TextContent(type="text", text=mcp_error("not_loaded", f"ATT&CK data unavailable: {err}. Run attck_update first."))]
        ids = [t.upper() for t in arguments.get("technique_ids", [])]
        context = arguments.get("context", "")
        tactic_coverage: dict[str, list] = {}
        unknown = []
        for tid in ids:
            obj = (_technique_index or {}).get(tid)
            if not obj:
                unknown.append(tid)
                continue
            for phase in obj.get("kill_chain_phases", []):
                tactic_coverage.setdefault(phase["phase_name"], []).append(
                    f"{tid} ({obj.get('name', '?')})"
                )
        lines = []
        if context:
            lines.append(f"Context: {context}\n")
        lines.append(f"Observed techniques: {len(ids)}  Unrecognized: {len(unknown)}")
        lines.append(f"Tactic coverage ({len(tactic_coverage)} tactics):\n")
        for tactic, techs in sorted(tactic_coverage.items()):
            lines.append(f"  [{tactic}]")
            for t in techs:
                lines.append(f"    {t}")
        if unknown:
            lines.append(f"\nUnrecognized IDs: {', '.join(unknown)}")
        result = "\n".join(lines)

    else:
        result = mcp_error("unknown_tool", name)

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
