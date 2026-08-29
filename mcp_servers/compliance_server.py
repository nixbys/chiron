"""
compliance_server.py

MCP server for NIST SP 800-53 Rev 5 control lookup and mapping. Same shape
as attck_server.py: fetch-and-cache a public dataset (NIST's free OSCAL
JSON catalog, republished by usnistgov/oscal-content on GitHub) and serve
lookups against the local cache.

CIS Controls v8 is deliberately out of scope -- unlike NIST's OSCAL
catalog, CIS's control text isn't freely redistributable, so bundling or
caching it here would be a licensing problem this project doesn't need.

nist_map's technique/tag -> control-family table is a small, hand-authored
heuristic (see _TAG_TO_FAMILIES below), not a real crosswalk -- it exists
to give a rough compliance-relevant grouping for a set of findings/
technique tags, not to be cited as authoritative NIST guidance. It keys on
ATT&CK *tactic phase names* (the same small, fixed vocabulary
attck_server.py's attck_tactic tool uses -- initial-access,
lateral-movement, etc.) and Odysseus's own finding tags/check types, not
individual ATT&CK technique IDs: a real technique-by-technique crosswalk
would be neither small nor realistically maintainable by hand, and this
server never imports attck_server.py to resolve one dynamically (MCP
servers in this fork are standalone subprocesses and never import each
other).
"""

import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

import requests

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import mcp_error

server = Server("compliance")

_DATA_DIR = Path(os.environ.get("ODYSSEUS_DATA_DIR", "./data"))
_CACHE_FILE = _DATA_DIR / "nist_800_53_rev5.json"
_CACHE_MAX_AGE = 7 * 24 * 3600  # 7 days

_NIST_CATALOG_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)

_PARAM_INSERT_RE = re.compile(r"\{\{\s*insert:\s*param,\s*[^}]+\}\}")

_cache: dict | None = None
# control id (lowercase, e.g. "ac-2" or "ac-2.1") -> {title, family_id, family_title, control}
_control_index: dict[str, dict] | None = None
# family id (lowercase, e.g. "ac") -> {"title": ..., "control_ids": [...]}
_family_index: dict[str, dict] | None = None


def _load_cache() -> dict | None:
    global _cache
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


def _fetch_catalog() -> str | None:
    """Fetch the NIST OSCAL catalog and cache it. Returns error string or None."""
    global _cache
    try:
        resp = requests.get(_NIST_CATALOG_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(json.dumps(data))
        _cache = data
        _build_indexes()
        return None
    except Exception as exc:  # noqa: BLE001
        return str(exc)


def _index_control(control: dict, family_id: str, family_title: str) -> None:
    """Index one control and recurse into its enhancements (OSCAL nests
    enhancements, e.g. ac-2.1, as a "controls" list on their parent)."""
    if _control_index is None:
        return
    cid = control.get("id", "").lower()
    if cid:
        _control_index[cid] = {
            "title": control.get("title", ""),
            "family_id": family_id,
            "family_title": family_title,
            "control": control,
        }
        _family_index.setdefault(family_id, {"title": family_title, "control_ids": []})["control_ids"].append(cid)
    for child in control.get("controls", []):
        _index_control(child, family_id, family_title)


def _build_indexes() -> None:
    global _control_index, _family_index
    if _cache is None:
        return
    _control_index = {}
    _family_index = {}
    for group in _cache.get("catalog", {}).get("groups", []):
        family_id = group.get("id", "").lower()
        family_title = group.get("title", "")
        for control in group.get("controls", []):
            _index_control(control, family_id, family_title)


def _ensure_loaded() -> str | None:
    if _load_cache() is not None:
        return None
    return _fetch_catalog()


def _control_statement(control: dict) -> str:
    """Render a control's statement text (OSCAL nests the actual
    requirement prose under parts, split into lettered/numbered items).
    Organization-defined-parameter placeholders are rendered as
    "[organization-defined]" rather than resolved against the control's
    own params list -- readable, not a verbatim legal transcription."""
    lines: list[str] = []

    def _walk(parts: list, indent: str) -> None:
        for part in parts:
            if part.get("name") in ("statement", "item") and part.get("prose"):
                prose = _PARAM_INSERT_RE.sub("[organization-defined]", part["prose"])
                lines.append(f"{indent}{prose}")
            _walk(part.get("parts", []), indent + "  ")

    for part in control.get("parts", []):
        if part.get("name") == "statement":
            _walk(part.get("parts", []) or [part], "")
    return "\n".join(lines) if lines else "(no statement text in catalog)"


def _control_guidance(control: dict) -> str:
    for part in control.get("parts", []):
        if part.get("name") == "guidance" and part.get("prose"):
            return part["prose"]
    return ""


def _related_control_ids(control: dict) -> list[str]:
    return sorted({
        link["href"].lstrip("#").split(".json#")[-1]
        for link in control.get("links", [])
        if link.get("rel") == "related" and link.get("href")
    })


# Heuristic technique/tag -> NIST 800-53 family mapping. See module
# docstring for why this stays small (ATT&CK tactic names + Odysseus's own
# tag vocabulary) rather than a per-technique crosswalk.
_TAG_TO_FAMILIES: dict[str, list[str]] = {
    # ATT&CK tactic phase names (attck_server.py's attck_tactic vocabulary)
    "reconnaissance": ["ra", "sc"],
    "resource-development": ["sa", "sr"],
    "initial-access": ["ac", "sc", "sa"],
    "execution": ["cm", "si"],
    "persistence": ["cm", "ac", "au"],
    "privilege-escalation": ["ac", "au"],
    "defense-evasion": ["si", "au", "cm"],
    "credential-access": ["ia", "ac"],
    "discovery": ["ac", "au", "sc"],
    "lateral-movement": ["ac", "sc", "cm"],
    "collection": ["mp", "sc", "si"],
    "command-and-control": ["sc", "si"],
    "exfiltration": ["sc", "si", "mp"],
    "impact": ["cp", "ir", "si"],
    # Odysseus finding tags / scheduled_recon check types (src/builtin_actions.py)
    "ports": ["cm", "sc"],
    "subdomains": ["cm", "sc", "sa"],
    "cert": ["sc", "ia"],
    "cve": ["ra", "si", "cm"],
    "watchlist": ["si", "ra"],
    "threat-intel": ["ra", "si"],
    "sigma": ["au", "si", "ir"],
    "yara": ["si", "ir"],
    "host-telemetry": ["cm", "au", "ac"],
    "drift": ["cm", "ca"],
    "continuous-monitoring": ["ca", "cm"],
}


TOOLS = [
    Tool(
        name="nist_update",
        description=(
            "Download or refresh the local NIST SP 800-53 Rev 5 OSCAL catalog. "
            "Data is cached for 7 days. Run this before first use or to get the latest catalog."
        ),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="nist_control",
        description="Look up a NIST 800-53 control by ID (e.g. AC-2 or AC-2.1 for an enhancement). Returns title, statement text, guidance, and related controls.",
        inputSchema={
            "type": "object",
            "properties": {"control_id": {"type": "string", "description": "Control ID, e.g. AC-2 or AC-2.1"}},
            "required": ["control_id"],
        },
    ),
    Tool(
        name="nist_family",
        description="List all controls under a NIST 800-53 control family (e.g. AC, SC, IA).",
        inputSchema={
            "type": "object",
            "properties": {"family_id": {"type": "string", "description": "Family ID, e.g. AC, SC, IA"}},
            "required": ["family_id"],
        },
    ),
    Tool(
        name="nist_search",
        description="Search NIST 800-53 control titles by keyword.",
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
        name="nist_map",
        description=(
            "Map a list of ATT&CK tactic names and/or Odysseus finding tags to NIST 800-53 "
            "control families via a small hand-authored heuristic table -- a rough grouping "
            "for a compliance summary, not authoritative NIST guidance."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "ATT&CK tactic names and/or finding tags, e.g. ['initial-access', 'ports', 'sigma']",
                },
                "context": {"type": "string", "default": ""},
            },
            "required": ["items"],
        },
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:  # noqa: C901
    if name == "nist_update":
        err = _fetch_catalog()
        if err:
            result = mcp_error("fetch_failed", f"Could not download NIST 800-53 catalog: {err}")
        else:
            result = f"NIST SP 800-53 Rev 5 catalog loaded: {len(_control_index or {})} controls indexed across {len(_family_index or {})} families."

    elif name == "nist_control":
        if err := _ensure_loaded():
            return [TextContent(type="text", text=mcp_error("not_loaded", f"NIST catalog unavailable: {err}. Run nist_update first."))]
        cid = arguments["control_id"].strip().lower()
        entry = (_control_index or {}).get(cid)
        if not entry:
            return [TextContent(type="text", text=mcp_error("not_found", f"Control {arguments['control_id']!r} not found"))]
        control = entry["control"]
        related = _related_control_ids(control)
        guidance = _control_guidance(control)[:600]
        result = (
            f"Control: {cid.upper()} — {entry['title']}\n"
            f"Family: {entry['family_id'].upper()} — {entry['family_title']}\n"
            f"Related: {', '.join(r.upper() for r in related) or 'none'}\n\n"
            f"Statement:\n{_control_statement(control)}"
        )
        if guidance:
            result += f"\n\nGuidance:\n{guidance}"

    elif name == "nist_family":
        if err := _ensure_loaded():
            return [TextContent(type="text", text=mcp_error("not_loaded", f"NIST catalog unavailable: {err}. Run nist_update first."))]
        fid = arguments["family_id"].strip().lower()
        family = (_family_index or {}).get(fid)
        if not family:
            available = ", ".join(sorted(f.upper() for f in (_family_index or {})))
            return [TextContent(type="text", text=f"Family {arguments['family_id']!r} not found.\nAvailable: {available}")]
        lines = [f"Family: {fid.upper()} — {family['title']} ({len(family['control_ids'])} controls)"]
        for cid in sorted(family["control_ids"]):
            lines.append(f"  {cid.upper():<12} {(_control_index or {})[cid]['title']}")
        result = "\n".join(lines)

    elif name == "nist_search":
        if err := _ensure_loaded():
            return [TextContent(type="text", text=mcp_error("not_loaded", f"NIST catalog unavailable: {err}. Run nist_update first."))]
        keyword = arguments["keyword"].lower()
        limit = int(arguments.get("limit", 20))
        matches = sorted(
            (cid, entry["title"]) for cid, entry in (_control_index or {}).items()
            if keyword in entry["title"].lower()
        )[:limit]
        if not matches:
            result = f"No controls found matching '{keyword}'."
        else:
            lines = [f"Found {len(matches)} match(es) for '{keyword}':"]
            for cid, title in matches:
                lines.append(f"  {cid.upper():<12} {title}")
            result = "\n".join(lines)

    elif name == "nist_map":
        items = [str(i).strip().lower() for i in arguments.get("items", []) if str(i).strip()]
        context = arguments.get("context", "")
        family_titles = {fid: fam["title"] for fid, fam in (_family_index or {}).items()} if _load_cache() else {}
        coverage: dict[str, set] = {}
        unmapped = []
        for item in items:
            families = _TAG_TO_FAMILIES.get(item)
            if not families:
                unmapped.append(item)
                continue
            for fam in families:
                coverage.setdefault(fam, set()).add(item)
        lines = []
        if context:
            lines.append(f"Context: {context}\n")
        lines.append(f"Mapped items: {len(items) - len(unmapped)}  Unmapped: {len(unmapped)}")
        lines.append(f"Control family coverage ({len(coverage)} families):")
        for fam in sorted(coverage):
            title = family_titles.get(fam, fam.upper())
            sources = ", ".join(sorted(coverage[fam]))
            lines.append(f"  [{fam.upper()}] {title} — from: {sources}")
        if unmapped:
            lines.append(f"\nUnmapped items: {', '.join(unmapped)}")
        result = "\n".join(lines)

    else:
        result = mcp_error("unknown_tool", name)

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
