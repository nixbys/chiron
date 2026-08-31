# routes/export_routes.py
"""Security Hub: bulk export of everything a security investigation
touches -- findings, the audit trail (including full raw tool output),
engagement metadata + timeline, assets/services, watchlist entries,
detection rules, and the existing one-call PDF report -- as one
downloadable .zip.

Same direct-import-of-mcp_servers-modules pattern security_dashboard_
routes.py already establishes (routes/ files may cross-import
mcp_servers modules; the no-cross-import rule is only
mcp_servers-to-mcp_servers), reusing that module's own `_list_*`/
`_export_*` structured-JSON helpers rather than re-deriving any of this
from scratch.

Two modes:
  - GET /api/security/export/engagement/{id} -- everything tied to one
    engagement_id, plus a freshly generated PDF summary for it.
  - GET /api/security/export/all -- everything across every engagement
    and all time, plus every already-generated PDF report and every
    rule file on disk. Does NOT force-generate a report per engagement
    (could be slow with many engagements) -- only bundles what's
    already there; see `_export_all` below.

Built entirely in memory (zipfile.ZipFile over io.BytesIO) -- matches
the scale this fork actually operates at (a single-operator workspace,
not a multi-tenant SOC backend); see mcp_servers/common.py's
_write_raw_log() for the per-call size cap that keeps this bounded in
practice.
"""

import asyncio
import io
import json
import logging
import zipfile
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response

from core.middleware import require_admin
from src.auth_helpers import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/security/export", tags=["security-export"])

# OpenSearch's own default index.max_result_window is 10000 -- see
# findings_server.py's _export_findings() docstring for the pagination
# caveat above that.
_FINDINGS_LIMIT = 10000
# Generous cap for a single export; audit_server.py's own _list_invocations
# has no hard upper bound, this just keeps one export request finite.
_AUDIT_LIMIT = 20000


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, indent=2, ensure_ascii=False, default=str).encode("utf-8")


def _add_raw_logs(zf: zipfile.ZipFile, invocations: list[dict]) -> int:
    """Copy each invocation's full raw-output file (written by
    mcp_servers/common.py's _write_raw_log()) into raw_logs/. Best-effort
    per file -- a missing/unreadable log (a pre-upgrade invocation with no
    raw_log_path, or a pruned data dir) is skipped, not fatal to the
    export as a whole."""
    import mcp_servers.common as common_mod
    added = 0
    for inv in invocations:
        rel = inv.get("raw_log_path")
        if not rel:
            continue
        try:
            text = (common_mod._DATA_DIR / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        zf.writestr(f"raw_logs/{inv['id']}_{inv['binary']}.log", text)
        added += 1
    return added


def _add_rule_files(zf: zipfile.ZipFile) -> None:
    """Bundle every stored Sigma/YARA rule -- these have no engagement_id
    of their own (global, not per-engagement), so this only runs for the
    "everything" export, not the per-engagement one."""
    try:
        import mcp_servers.sigma_server as sigma_mod
        for name in sigma_mod._list_rules():
            content, err = sigma_mod._read_rule(name)
            if not err:
                zf.writestr(f"rules/sigma/{name}.yml", content)
    except Exception:  # noqa: BLE001
        logger.warning("Failed to bundle Sigma rules into export", exc_info=True)
    try:
        import mcp_servers.yara_server as yara_mod
        for name in yara_mod._list_rule_names() or []:
            content, err = yara_mod._read_rule(name)
            if not err:
                zf.writestr(f"rules/yara/{name}", content)
    except Exception:  # noqa: BLE001
        logger.warning("Failed to bundle YARA rules into export", exc_info=True)


def _zip_response(buf: io.BytesIO, filename: str) -> Response:
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _build_engagement_zip(
    engagement: dict, timeline: list[dict], findings: list[dict], asset_data: dict,
    watchlist: list[dict], invocations: list[dict], report_bytes: bytes | None,
    exported_by: str | None,
) -> io.BytesIO:
    """Synchronous, CPU/IO-bound zip assembly -- called via asyncio.to_thread
    so it doesn't block the event loop while compressing raw logs."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("engagement.json", _json_bytes({"engagement": engagement, "timeline": timeline}))
        zf.writestr("findings.json", _json_bytes(findings))
        zf.writestr("assets.json", _json_bytes(asset_data))
        zf.writestr("watchlist.json", _json_bytes(watchlist))
        zf.writestr("audit_log.json", _json_bytes(invocations))
        raw_log_count = _add_raw_logs(zf, invocations)
        if report_bytes:
            zf.writestr("report.pdf", report_bytes)
        zf.writestr("manifest.json", _json_bytes({
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "exported_by": exported_by,
            "engagement_id": engagement.get("id"),
            "counts": {
                "timeline_events": len(timeline),
                "findings": len(findings),
                "assets": len(asset_data.get("assets", [])),
                "services": len(asset_data.get("services", [])),
                "local_findings": len(asset_data.get("findings", [])),
                "watchlist_entries": len(watchlist),
                "audit_invocations": len(invocations),
                "raw_logs_included": raw_log_count,
            },
            "report_included": report_bytes is not None,
        }))
    buf.seek(0)
    return buf


def _build_all_zip(
    engagements: list[dict], findings: list[dict], asset_data: dict, watchlist: list[dict],
    invocations: list[dict], exported_by: str | None, reports_dir,
) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("engagements.json", _json_bytes(engagements))
        zf.writestr("findings.json", _json_bytes(findings))
        zf.writestr("assets.json", _json_bytes(asset_data))
        zf.writestr("watchlist.json", _json_bytes(watchlist))
        zf.writestr("audit_log.json", _json_bytes(invocations))
        raw_log_count = _add_raw_logs(zf, invocations)
        _add_rule_files(zf)
        # Bundle whatever engagement report PDFs already exist on disk
        # rather than force-generating one per engagement here (could be
        # slow/expensive with many engagements) -- see module docstring.
        report_count = 0
        if reports_dir.is_dir():
            for f in reports_dir.glob("*.pdf"):
                try:
                    zf.writestr(f"reports/{f.name}", f.read_bytes())
                    report_count += 1
                except OSError:
                    continue
        zf.writestr("manifest.json", _json_bytes({
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "exported_by": exported_by,
            "scope": "all",
            "counts": {
                "engagements": len(engagements),
                "findings": len(findings),
                "assets": len(asset_data.get("assets", [])),
                "services": len(asset_data.get("services", [])),
                "local_findings": len(asset_data.get("findings", [])),
                "watchlist_entries": len(watchlist),
                "audit_invocations": len(invocations),
                "raw_logs_included": raw_log_count,
                "reports_included": report_count,
            },
        }))
    buf.seek(0)
    return buf


def setup_export_routes() -> APIRouter:
    @router.get("/engagement/{engagement_id}")
    async def export_engagement(request: Request, engagement_id: str):
        require_admin(request)
        user = get_current_user(request)
        import mcp_servers.asset_server as asset_mod
        import mcp_servers.audit_server as audit_mod
        import mcp_servers.engagement_server as engagement_mod
        import mcp_servers.findings_server as findings_mod
        import mcp_servers.pdf_server as pdf_mod
        import mcp_servers.watchlist_server as watchlist_mod

        engagement = await asyncio.to_thread(engagement_mod._get_engagement, engagement_id)
        if engagement is None:
            raise HTTPException(404, f"No engagement with id {engagement_id!r}")
        for field in ("scope", "out_of_scope", "tags", "blackout_dates"):
            engagement[field] = json.loads(engagement.get(field) or "[]")
        timeline = await asyncio.to_thread(engagement_mod._get_timeline, engagement_id, 5000)

        invocations, findings, asset_data, watchlist = await asyncio.gather(
            asyncio.to_thread(audit_mod._list_invocations, engagement_id=engagement_id, limit=_AUDIT_LIMIT),
            asyncio.to_thread(findings_mod._export_findings, engagement=engagement_id, size=_FINDINGS_LIMIT),
            asyncio.to_thread(asset_mod._export_data, engagement_id=engagement_id, limit=5000),
            asyncio.to_thread(watchlist_mod._list_watchlist, None, engagement_id, ""),
        )

        # Reuse the existing one-call PDF report rather than reimplementing
        # a second summary format -- generated fresh so it reflects
        # everything above, not a stale prior run.
        report_rel_path = f"reports/export_{engagement_id}.pdf"
        report_text = await asyncio.to_thread(
            pdf_mod._generate_engagement_report,
            engagement_id, report_rel_path, user or "export", "true", 100,
        )
        report_bytes = None
        if not report_text.startswith("[error]"):
            try:
                report_bytes = (pdf_mod._DATA_DIR / report_rel_path).read_bytes()
            except OSError:
                report_bytes = None

        buf = await asyncio.to_thread(
            _build_engagement_zip, engagement, timeline, findings, asset_data,
            watchlist, invocations, report_bytes, user,
        )
        filename = f"chiron_export_{engagement_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        return _zip_response(buf, filename)

    @router.get("/all")
    async def export_all(request: Request):
        require_admin(request)
        user = get_current_user(request)
        import mcp_servers.asset_server as asset_mod
        import mcp_servers.audit_server as audit_mod
        import mcp_servers.engagement_server as engagement_mod
        import mcp_servers.findings_server as findings_mod
        import mcp_servers.pdf_server as pdf_mod
        import mcp_servers.watchlist_server as watchlist_mod

        engagement_summaries = await asyncio.to_thread(engagement_mod._list_engagements, None, 1000)

        async def _hydrate(summary: dict) -> dict:
            full = await asyncio.to_thread(engagement_mod._get_engagement, summary["id"])
            if full is None:
                return summary
            for field in ("scope", "out_of_scope", "tags", "blackout_dates"):
                full[field] = json.loads(full.get(field) or "[]")
            full["timeline"] = await asyncio.to_thread(engagement_mod._get_timeline, summary["id"], 5000)
            return full

        engagements = await asyncio.gather(*[_hydrate(e) for e in engagement_summaries])
        engagements = list(engagements)

        invocations, findings, asset_data, watchlist = await asyncio.gather(
            asyncio.to_thread(audit_mod._list_invocations, limit=_AUDIT_LIMIT),
            asyncio.to_thread(findings_mod._export_findings, engagement=None, size=_FINDINGS_LIMIT),
            asyncio.to_thread(asset_mod._export_data, engagement_id=None, limit=20000),
            asyncio.to_thread(watchlist_mod._list_watchlist, None, None, ""),
        )

        buf = await asyncio.to_thread(
            _build_all_zip, engagements, findings, asset_data, watchlist,
            invocations, user, pdf_mod._DATA_DIR / "reports",
        )
        filename = f"chiron_export_all_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        return _zip_response(buf, filename)

    return router
