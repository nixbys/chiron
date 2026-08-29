# routes/security_dashboard_routes.py
"""Security dashboard: one admin-gated endpoint aggregating a snapshot
across the security MCP servers' own stores.

This is the minimal v1 page -- a later pass turns it into the full
Security Hub anchor (engagement/watchlist/rule-management sub-panels,
new design system), not a bigger version of this same page.

Reads each source via direct import of the relevant mcp_servers module
(bypassing the MCP text-tool interface for structured data) rather than
through the MCP manager -- routes/ files can cross-import mcp_servers
modules; the no-cross-import rule is only mcp_servers-to-mcp_servers.
Every source is best-effort: one section failing (e.g. OpenSearch
unreachable) surfaces as an `error` field on that section, not a 500 for
the whole dashboard.
"""

import asyncio
import json
import logging

from fastapi import APIRouter, Request

from core.middleware import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/security", tags=["security-dashboard"])


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


def setup_security_dashboard_routes():
    """Setup the security dashboard route. Mirrors setup_mcp_routes'
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

    return router
