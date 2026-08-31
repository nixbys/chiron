# routes/security_dashboard_routes.py
"""Security Hub: the admin-gated dashboard snapshot, plus management
sub-panels for engagements, the watchlist, and Sigma/YARA rules.

Reads each source via direct import of the relevant mcp_servers module
(bypassing the MCP text-tool interface for structured data) rather than
through the MCP manager -- routes/ files can cross-import mcp_servers
modules; the no-cross-import rule is only mcp_servers-to-mcp_servers.
Every dashboard section is best-effort: one section failing (e.g.
OpenSearch unreachable) surfaces as an `error` field on that section, not
a 500 for the whole dashboard.

Writes (create/update/close an engagement, add/remove/pause a watchlist
entry) go through the *same* MCP server module's `call_tool()` that the
chat/MCP-tool path uses -- `_call_tool()` below awaits it directly and
maps its `[error:code]` text convention onto an HTTP status, so there is
exactly one place each write's validation/business logic lives, not a
second copy reimplemented in SQL here. Reads that need structured JSON
(not text-table output) go through small `_list_*`/`_get_*` helpers each
module exposes for direct import, same pattern `_list_engagements` /
`_list_active_watchlist` already established for the dashboard's own
summary sections.
"""

import asyncio
import json
import logging
import os
import re
import uuid

import requests
from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from core.middleware import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/security", tags=["security-dashboard"])

# Maps an MCP `[error:<code>]` code onto an HTTP status. Anything not
# listed here (a validation error like `invalid_kind`, `invalid_hash`,
# `db_error`) falls back to 400 -- "the request itself was bad" is the
# correct default for this fork's MCP servers' error vocabulary.
_ERROR_STATUS = {"not_found": 404, "duplicate": 409}


def _fetch_findings_summary() -> dict:
    """Same aggregation query as findings_server.py's finding_stats tool
    (mcp_servers/findings_server.py), called directly for structured data
    instead of formatted text."""
    import mcp_servers.findings_server as findings_mod
    try:
        if err := findings_mod._ensure_index():
            return {"error": err}
        body = {
            "size": 0,
            "aggs": {
                "by_severity": {"terms": {"field": "severity", "size": 5}},
                "by_status": {"terms": {"field": "status", "size": 5}},
            },
        }
        resp = findings_mod._req("POST", f"/{findings_mod._INDEX}/_search", body)
        aggs = resp.get("aggregations", {})
        return {
            "total": resp.get("hits", {}).get("total", {}).get("value", 0),
            "by_severity": aggs.get("by_severity", {}).get("buckets", []),
            "by_status": aggs.get("by_status", {}).get("buckets", []),
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _fetch_watchlist_summary() -> dict:
    import mcp_servers.watchlist_server as watchlist_mod
    try:
        entries = watchlist_mod._list_active_watchlist()
        return {
            "count": len(entries),
            "entries": [
                {"indicator": e["indicator"], "kind": e["kind"], "engagement_id": e.get("engagement_id")}
                for e in entries[:20]
            ],
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _fetch_scan_drift(limit: int) -> dict:
    import mcp_servers.monitor_server as monitor_mod
    try:
        diffs = monitor_mod._list_recent_diffs(limit=limit)
        for d in diffs:
            d["added"] = json.loads(d.get("added") or "[]")
            d["removed"] = json.loads(d.get("removed") or "[]")
        return {"diffs": diffs}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _fetch_engagements(limit: int) -> dict:
    import mcp_servers.engagement_server as engagement_mod
    try:
        return {"list": engagement_mod._list_engagements(limit=limit)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _fetch_host_telemetry_summary() -> dict:
    """Counts only -- the dashboard summarizes, it doesn't dump full
    process/socket listings (see host_telemetry_server's own tools for
    that). Best-effort: psutil access can fail under a restricted
    container, and this is a nice-to-have panel, not core dashboard data."""
    try:
        import mcp_servers.host_telemetry_server as host_mod
    except Exception as exc:  # noqa: BLE001
        return {"error": f"host_telemetry_server unavailable: {exc}"}
    summary: dict = {}
    procs = host_mod._processes_fetch()
    if "_mcp_error" not in procs:
        summary["process_count"] = len(procs["processes"])
    ports = host_mod._listening_ports_fetch()
    if "_mcp_error" not in ports:
        summary["listening_port_count"] = len(ports["listening"])
    users = host_mod._users_fetch()
    if "_mcp_error" not in users:
        summary["logged_in_user_count"] = len(users["users"])
    if not summary:
        return {"error": "host telemetry unavailable"}
    return summary


# Connected sidecar services (Security Hub's own "Connected Services" tab).
# `browser_url` is what a human clicks -- always loopback-only (never
# 0.0.0.0, see docker-compose.security.yml) so this only ever works from the
# machine Chiron itself runs on. `probe_url` is the *internal* Docker/Podman
# network address this server container actually reaches each sidecar
# through (matches docker-compose.security.yml's own env var defaults for
# the `odysseus` service) -- checking reachability from here avoids a
# browser-side CORS probe entirely and mirrors how the Overview tab's own
# findings-summary section already treats OpenSearch as best-effort.
# `browser_url: None` means intentionally never exposed to a browser (the
# toolchain's exec API accepts arbitrary command execution -- see ADR 001,
# SECURITY.md "Toolchain Container Hardening").
_CONNECTED_SERVICES = [
    {
        "id": "bentopdf", "label": "BentoPDF",
        "description": "Client-side PDF toolkit — metadata, redaction, report assembly.",
        "browser_url": os.environ.get("BENTOPDF_URL", "http://localhost:3000"),
        "probe_url": "http://odysseus-bentopdf:8080/", "has_ui": True,
    },
    {
        "id": "cyberchef", "label": "CyberChef",
        "description": "Manual data-transformation workbench — decode/encode/hash/beautify by hand.",
        "browser_url": "http://localhost:8000",
        "probe_url": "http://odysseus-cyberchef:8000/", "has_ui": True,
    },
    {
        "id": "spiderfoot", "label": "SpiderFoot",
        "description": "Correlated OSINT scanning — 200+ modules.",
        "browser_url": "http://localhost:5001",
        "probe_url": os.environ.get("SPIDERFOOT_URL", "http://odysseus-spiderfoot:5001").rstrip("/") + "/",
        "has_ui": True,
    },
    {
        "id": "opensearch", "label": "OpenSearch",
        "description": "Findings persistence index — REST API, no bundled Dashboards UI.",
        "browser_url": "http://localhost:9200",
        "probe_url": os.environ.get("OPENSEARCH_URL", "http://odysseus-opensearch:9200").rstrip("/") + "/",
        "has_ui": False,
    },
    {
        "id": "ollama", "label": "Ollama",
        "description": "Local LLM runtime — REST API, no UI.",
        "browser_url": "http://localhost:11434",
        "probe_url": os.environ.get("OLLAMA_BASE_URL", "http://odysseus-ollama:11434/v1").rsplit("/v1", 1)[0].rstrip("/") + "/",
        "has_ui": False,
    },
    {
        "id": "toolchain", "label": "Kali Toolchain",
        "description": "Exec API — internal-only by design, never exposed to the browser (arbitrary command execution surface).",
        "browser_url": None,
        "probe_url": os.environ.get("ODYSSEUS_TOOLCHAIN_API", "http://odysseus-toolchain:8088").rstrip("/") + "/health",
        "has_ui": False,
    },
]


def _probe_service(url: str) -> bool:
    try:
        resp = requests.get(url, timeout=2)
        return resp.status_code < 500
    except Exception:  # noqa: BLE001
        return False


async def _call_tool(mod, tool_name: str, arguments: dict) -> str:
    """Await one MCP server module's call_tool() directly and map its
    `[error:code]` text convention onto an HTTPException, or return the
    raw result text on success. This is the one place a write from the
    Security Hub UI touches server state -- same function, same
    validation, as the chat/MCP-tool path; see the module docstring."""
    results = await mod.call_tool(tool_name, arguments)
    text = results[0].text
    if match := re.match(r"^\[error:(\w+)\]\s*(.*)", text):
        code, message = match.group(1), match.group(2)
        raise HTTPException(_ERROR_STATUS.get(code, 400), message or text)
    return text


_CREATED_ID_RE = re.compile(r"\(id=([0-9a-f]+)\)")

# ---- RoE/SOW scope extraction (Phase E) --------------------------------
#
# Pulls IP/CIDR/domain-looking tokens out of an uploaded authorization
# document's extracted text, for the "New Project" flow to offer as an
# *editable, pre-filled* candidate scope list -- never auto-committed as
# an authorization boundary. Same validators mcp_servers/common.py's own
# tools already use, so "looks like a real target" here means the same
# thing it means everywhere else in this fork.
_IP_CIDR_TOKEN_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_DOMAIN_TOKEN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b")
# A domain-shaped token that's actually a scope-document footer artifact,
# not a target -- filtered out even though it passes validate_domain().
_DOMAIN_TOKEN_DENYLIST = {"e.g", "i.e", "etc.com"}


def _extract_candidate_targets(text: str) -> list[str]:
    import mcp_servers.common as common_mod
    candidates: set[str] = set()
    for token in _IP_CIDR_TOKEN_RE.findall(text):
        if common_mod.validate_ip(token) is None:
            candidates.add(token)
    for token in _DOMAIN_TOKEN_RE.findall(text):
        low = token.lower().rstrip(".")
        if low in _DOMAIN_TOKEN_DENYLIST:
            continue
        if common_mod.validate_domain(low) is None:
            candidates.add(low)
    return sorted(candidates)


# A HH:MM-HH:MM (or "to"/"through"/en-dash/em-dash separated) time window,
# and any ISO date near the word "blackout" -- both best-effort, both
# pre-filled for review like the target candidates above, never
# auto-committed. Phase I's check_scope() only understands the strict
# HH:MM-HH:MM shape (see mcp_servers/common.py's _AUTHORIZED_HOURS_RE), so
# this normalizes to that before returning a candidate.
_TIME_WINDOW_RE = re.compile(r"\b(\d{1,2}):(\d{2})\s*(?:-|to|through|–|—)\s*(\d{1,2}):(\d{2})\b", re.IGNORECASE)
_ISO_DATE_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")


def _extract_candidate_temporal_scope(text: str) -> dict:
    authorized_hours = ""
    m = _TIME_WINDOW_RE.search(text)
    if m:
        sh, sm, eh, em = m.groups()
        authorized_hours = f"{int(sh):02d}:{sm}-{int(eh):02d}:{em}"

    blackout_dates: set[str] = set()
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        if "blackout" in sentence.lower():
            blackout_dates.update(_ISO_DATE_RE.findall(sentence))

    return {"authorized_hours": authorized_hours, "blackout_dates": sorted(blackout_dates)}


class EngagementCreateBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    client: str = ""
    scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    authorized_hours: str = ""
    blackout_dates: list[str] = Field(default_factory=list)


class EngagementUpdateBody(BaseModel):
    description: str | None = None
    client: str | None = None
    scope: list[str] | None = None
    out_of_scope: list[str] | None = None
    tags: list[str] | None = None
    authorized_hours: str | None = None
    blackout_dates: list[str] | None = None


class WatchlistAddBody(BaseModel):
    indicator: str = Field(..., min_length=1, max_length=500)
    kind: str
    engagement_id: str | None = None
    notes: str = ""
    source: str = "manual"


def setup_security_dashboard_routes():
    """Setup the Security Hub routes. Mirrors setup_mcp_routes'
    factory-function shape (routes/mcp/mcp_routes.py) for consistency,
    even though this router doesn't need any injected dependency yet."""

    @router.get("/dashboard")
    async def get_dashboard(request: Request, limit: int = 20):
        require_admin(request)
        limit = max(1, min(limit, 100))

        findings, watchlist, scan_drift, engagements, host_telemetry = await asyncio.gather(
            asyncio.to_thread(_fetch_findings_summary),
            asyncio.to_thread(_fetch_watchlist_summary),
            asyncio.to_thread(_fetch_scan_drift, limit),
            asyncio.to_thread(_fetch_engagements, limit),
            asyncio.to_thread(_fetch_host_telemetry_summary),
        )
        return {
            "findings": findings,
            "watchlist": watchlist,
            "scan_drift": scan_drift,
            "engagements": engagements,
            "host_telemetry": host_telemetry,
        }

    # ---- Engagements ----------------------------------------------------

    @router.get("/engagements")
    async def list_engagements(request: Request, status: str | None = None, limit: int = 50):
        require_admin(request)
        import mcp_servers.engagement_server as mod
        limit = max(1, min(limit, 200))
        return {"list": await asyncio.to_thread(mod._list_engagements, status, limit)}

    @router.get("/engagements/{engagement_id}")
    async def get_engagement(request: Request, engagement_id: str, timeline_limit: int = 200):
        require_admin(request)
        import mcp_servers.engagement_server as mod
        engagement = await asyncio.to_thread(mod._get_engagement, engagement_id)
        if engagement is None:
            raise HTTPException(404, f"No engagement with id {engagement_id!r}")
        for field in ("scope", "out_of_scope", "tags", "blackout_dates"):
            engagement[field] = json.loads(engagement.get(field) or "[]")
        timeline = await asyncio.to_thread(mod._get_timeline, engagement_id, max(1, min(timeline_limit, 1000)))
        return {"engagement": engagement, "timeline": timeline}

    @router.post("/engagements", status_code=201)
    async def create_engagement(request: Request, body: EngagementCreateBody):
        require_admin(request)
        import mcp_servers.engagement_server as mod
        text = await _call_tool(mod, "engagement_create", body.model_dump())
        match = _CREATED_ID_RE.search(text)
        return {"message": text, "engagement_id": match.group(1) if match else None}

    @router.patch("/engagements/{engagement_id}")
    async def update_engagement(request: Request, engagement_id: str, body: EngagementUpdateBody):
        require_admin(request)
        import mcp_servers.engagement_server as mod
        args = {"engagement_id": engagement_id, **{k: v for k, v in body.model_dump().items() if v is not None}}
        return {"message": await _call_tool(mod, "engagement_update", args)}

    @router.post("/engagements/{engagement_id}/close")
    async def close_engagement(request: Request, engagement_id: str):
        require_admin(request)
        import mcp_servers.engagement_server as mod
        return {"message": await _call_tool(mod, "engagement_close", {"engagement_id": engagement_id})}

    @router.post("/roe/parse-scope")
    async def parse_roe_scope(request: Request, file: UploadFile = File(...)):
        """Extract candidate in/out-of-scope targets from an uploaded Rules-
        of-Engagement/SOW PDF, for the "New Project" flow to pre-fill --
        the caller still reviews and confirms before anything is created,
        this never writes an engagement itself."""
        require_admin(request)
        import mcp_servers.pdf_server as pdf_mod
        if not getattr(pdf_mod, "_PYPDF_AVAILABLE", False):
            raise HTTPException(400, "PDF support isn't installed on this server (the 'pypdf' package is missing)")

        content = await file.read()
        _MAX_UPLOAD_BYTES = 20 * 1024 * 1024
        if len(content) > _MAX_UPLOAD_BYTES:
            raise HTTPException(400, f"File too large (max {_MAX_UPLOAD_BYTES // (1024 * 1024)}MB)")

        # A throwaway temp file under pdf_server's own data dir, so
        # _pdf_extract_text's existing _resolve() path-traversal guard
        # applies here too rather than a second one reimplemented in this
        # route -- deleted again once text extraction is done, since this
        # is a scope-parsing scratch file, not a document meant to persist.
        upload_dir = pdf_mod._DATA_DIR / "tmp_roe_uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        safe_name = f"{uuid.uuid4().hex}.pdf"
        dest = upload_dir / safe_name
        dest.write_bytes(content)
        try:
            text = await asyncio.to_thread(pdf_mod._pdf_extract_text, f"tmp_roe_uploads/{safe_name}", "", 0)
        finally:
            try:
                dest.unlink()
            except OSError:
                pass

        if text.startswith("[error]"):
            raise HTTPException(400, text)
        if text.startswith("(no extractable text"):
            return {"candidates": [], "extracted_chars": 0, "message": text, "authorized_hours": "", "blackout_dates": []}
        return {
            "candidates": _extract_candidate_targets(text),
            "extracted_chars": len(text),
            **_extract_candidate_temporal_scope(text),
        }

    # ---- Watchlist --------------------------------------------------------

    @router.get("/watchlist")
    async def list_watchlist(
        request: Request, kind: str | None = None, engagement_id: str | None = None, status: str = "active",
    ):
        require_admin(request)
        import mcp_servers.watchlist_server as mod
        return {"list": await asyncio.to_thread(mod._list_watchlist, kind, engagement_id, status)}

    @router.post("/watchlist", status_code=201)
    async def add_watchlist_entry(request: Request, body: WatchlistAddBody):
        require_admin(request)
        import mcp_servers.watchlist_server as mod
        return {"message": await _call_tool(mod, "watchlist_add", body.model_dump())}

    @router.delete("/watchlist/{watchlist_id}")
    async def remove_watchlist_entry(request: Request, watchlist_id: int):
        require_admin(request)
        import mcp_servers.watchlist_server as mod
        return {"message": await _call_tool(mod, "watchlist_remove", {"watchlist_id": watchlist_id})}

    @router.post("/watchlist/{watchlist_id}/pause")
    async def pause_watchlist_entry(request: Request, watchlist_id: int):
        require_admin(request)
        import mcp_servers.watchlist_server as mod
        return {"message": await _call_tool(mod, "watchlist_pause", {"watchlist_id": watchlist_id})}

    @router.post("/watchlist/{watchlist_id}/resume")
    async def resume_watchlist_entry(request: Request, watchlist_id: int):
        require_admin(request)
        import mcp_servers.watchlist_server as mod
        return {"message": await _call_tool(mod, "watchlist_resume", {"watchlist_id": watchlist_id})}

    @router.get("/watchlist/{watchlist_id}/checks")
    async def get_watchlist_checks(request: Request, watchlist_id: int):
        require_admin(request)
        import mcp_servers.watchlist_server as mod
        checks = await asyncio.to_thread(mod._list_checks, watchlist_id)
        for c in checks:
            c["snapshot"] = json.loads(c["snapshot"])
        return {"checks": checks}

    # ---- Rules (Sigma / YARA) ---------------------------------------------

    @router.get("/rules/sigma")
    async def list_sigma_rules(request: Request):
        require_admin(request)
        import mcp_servers.sigma_server as mod
        return {"list": await asyncio.to_thread(mod._list_rules)}

    @router.get("/rules/sigma/{name}")
    async def get_sigma_rule(request: Request, name: str):
        require_admin(request)
        import mcp_servers.sigma_server as mod
        content, err = await asyncio.to_thread(mod._read_rule, name)
        if err:
            raise HTTPException(404, err)
        return {"name": name, "content": content}

    @router.get("/rules/yara")
    async def list_yara_rules(request: Request):
        require_admin(request)
        import mcp_servers.yara_server as mod
        names = await asyncio.to_thread(mod._list_rule_names)
        if names is None:
            return {"list": [], "error": "toolchain sidecar unreachable"}
        return {"list": names}

    @router.get("/rules/yara/{name}")
    async def get_yara_rule(request: Request, name: str):
        require_admin(request)
        import mcp_servers.yara_server as mod
        content, err = await asyncio.to_thread(mod._read_rule, name)
        if err:
            raise HTTPException(404, err)
        return {"name": name, "content": content}

    # ---- Connected Services --------------------------------------------

    @router.get("/services")
    async def list_connected_services(request: Request):
        require_admin(request)

        async def _check(svc: dict) -> dict:
            reachable = await asyncio.to_thread(_probe_service, svc["probe_url"])
            return {k: v for k, v in svc.items() if k != "probe_url"} | {"reachable": reachable}

        results = await asyncio.gather(*[_check(s) for s in _CONNECTED_SERVICES])
        return {"services": results}

    # ---- Audit Log ----------------------------------------------------

    @router.get("/audit")
    async def list_audit_log(
        request: Request,
        binary: str | None = None,
        outcome: str | None = None,
        engagement_id: str | None = None,
        limit: int = 100,
    ):
        require_admin(request)
        import mcp_servers.audit_server as mod
        limit = max(1, min(limit, 500))
        # Sequential, not asyncio.gather -- both hit audit_server.py's own
        # lazily-initialized SQLite file (_get_db()'s CREATE TABLE IF NOT
        # EXISTS runs once, guarded by a plain bool flag, same pattern
        # every other mcp_servers/*.py store uses). Running them
        # concurrently on the very first request (nothing has written to
        # audit.db yet) raced two threads through that one-time schema
        # setup and hit a real "database is locked" 500 in practice.
        invocations = await asyncio.to_thread(
            mod._list_invocations, binary=binary, outcome=outcome,
            engagement_id=engagement_id, limit=limit,
        )
        stats = await asyncio.to_thread(mod._stats, 86400)
        return {"invocations": invocations, "stats": stats}

    return router
