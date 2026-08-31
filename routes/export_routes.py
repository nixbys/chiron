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
  - POST /api/security/export/engagement/{id} -- everything tied to one
    engagement_id, plus a freshly generated PDF summary for it.
  - POST /api/security/export/all -- everything across every engagement
    and all time, plus every already-generated PDF report and every
    rule file on disk. Does NOT force-generate a report per engagement
    (could be slow with many engagements) -- only bundles what's
    already there; see `_export_all` below.
Both accept an optional `passphrase` in the JSON body -- if given, the
whole zip is encrypted (see encrypt_export_bytes below) before being
served, and a best-effort export-complete notification fires via the
app's existing reminder-dispatch channel. POST (not GET) so the
passphrase never rides in a URL/query string.

  - DELETE /api/security/export/engagement/{id}?confirm=true -- wipes
    everything that engagement's export covers (findings, audit trail +
    raw logs, assets/services, watchlist entries, timeline) and closes
    the engagement. Irreversible; requires `confirm=true` so it can never
    fire from a plain link.
  - DELETE /api/security/export/all?confirm=true -- the same, unscoped,
    across every engagement.

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
import os
import zipfile
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from core.middleware import require_admin
from src.auth_helpers import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/security/export", tags=["security-export"])

# ---------------------------------------------------------------------------
# Optional passphrase encryption of the whole export bundle
# ---------------------------------------------------------------------------
#
# A password-protected *standard* zip (the kind any archive tool opens
# directly) needs AES-zip support neither Python's stdlib zipfile nor this
# repo's existing dependencies provide. Rather than add a new dependency
# for that, this wraps the already-built zip bytes in one more envelope
# using `cryptography` (already a dependency, same library
# src/secret_storage.py itself is built on): a random per-export salt,
# PBKDF2-HMAC-SHA256 to derive a key from the passphrase, then Fernet.
# The passphrase is never sent anywhere but this one request and is never
# stored server-side. Opening the result needs scripts/decrypt_export.py
# (or the same three-line recipe) -- not a plain double-click in a file
# manager -- which is the deliberate tradeoff for not adding a dependency
# for this one feature.
_EXPORT_MAGIC = b"CHIRONEXPORT1\n"
_PBKDF2_ITERATIONS = 600_000  # OWASP's current (2023+) minimum for PBKDF2-HMAC-SHA256
_SALT_LEN = 16


def _derive_export_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_PBKDF2_ITERATIONS)
    import base64
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_export_bytes(data: bytes, passphrase: str) -> bytes:
    salt = os.urandom(_SALT_LEN)
    key = _derive_export_key(passphrase, salt)
    token = Fernet(key).encrypt(data)
    return _EXPORT_MAGIC + salt + token


def decrypt_export_bytes(blob: bytes, passphrase: str) -> bytes:
    """Reverse of encrypt_export_bytes() -- used by scripts/decrypt_export.py
    and its own tests. Raises ValueError on a non-Chiron-export file or a
    wrong passphrase (never a raw cryptography exception, so callers don't
    need to know Fernet's own exception types)."""
    if not blob.startswith(_EXPORT_MAGIC):
        raise ValueError("Not a Chiron encrypted export file (missing header)")
    rest = blob[len(_EXPORT_MAGIC):]
    salt, token = rest[:_SALT_LEN], rest[_SALT_LEN:]
    key = _derive_export_key(passphrase, salt)
    try:
        return Fernet(key).decrypt(token)
    except InvalidToken:
        raise ValueError("Wrong passphrase, or the file is corrupted") from None


class ExportRequestBody(BaseModel):
    passphrase: str = ""


async def _notify_export_complete(engagement_id: str | None, user: str | None) -> None:
    """Best-effort notification via the app's existing reminder-dispatch
    channel (routes/note_routes.py's dispatch_reminder -- the same one
    ADR 007's detection pipeline already uses for security_finding_added,
    see src/builtin_actions.py's own scheduled-check dispatch calls for
    the established call shape this mirrors) -- browser/email/ntfy/
    webhook, whichever the user has configured. A notification failure
    must never fail the export itself, which has already succeeded and
    is already in the response by the time this runs."""
    import time
    try:
        from routes.note_routes import dispatch_reminder
        label = f"engagement {engagement_id}" if engagement_id else "everything"
        await dispatch_reminder(
            title="Chiron export complete",
            note_body=f"Your export of {label} finished and is ready to download.",
            note_id=f"export-{engagement_id or 'all'}-{int(time.time())}",
            owner=user or "",
        )
    except Exception:  # noqa: BLE001
        logger.warning("Export-complete notification failed", exc_info=True)

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
    """Copy each invocation's full raw-output file (written, encrypted at
    rest, by mcp_servers/common.py's _write_raw_log()) into raw_logs/ --
    decrypted, via that module's _read_raw_log(), so the export itself
    stays plain-text-readable (the zip as a whole is the thing optionally
    passphrase-encrypted -- see encrypt_export_bytes -- not each member
    file individually). Best-effort per file -- a missing/unreadable log
    (a pre-upgrade invocation with no raw_log_path, or a pruned data dir)
    is skipped, not fatal to the export as a whole."""
    import mcp_servers.common as common_mod
    added = 0
    for inv in invocations:
        rel = inv.get("raw_log_path")
        if not rel:
            continue
        try:
            text = common_mod._read_raw_log(rel)
        except OSError:
            continue
        zf.writestr(f"raw_logs/{inv['id']}_{inv['binary']}.log", text)
        added += 1
    return added


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_breakdown(findings: list[dict]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    if not counts:
        return "no findings recorded"
    ordered = sorted(counts.items(), key=lambda kv: _SEVERITY_ORDER.get(kv[0], 99))
    return ", ".join(f"{n} {sev}" for sev, n in ordered)


def _notable_findings(findings: list[dict], limit: int = 10) -> list[dict]:
    ranked = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(str(f.get("severity") or "").lower(), 99))
    return ranked[:limit]


def _audit_outcome_breakdown(invocations: list[dict]) -> str:
    counts: dict[str, int] = {}
    for inv in invocations:
        outcome = inv.get("outcome") or "unknown"
        counts[outcome] = counts.get(outcome, 0) + 1
    if not counts:
        return "no toolchain activity recorded"
    return ", ".join(f"{n} {outcome}" for outcome, n in sorted(counts.items(), key=lambda kv: -kv[1]))


def _build_engagement_summary_md(
    engagement: dict, timeline: list[dict], findings: list[dict], asset_data: dict,
    watchlist: list[dict], invocations: list[dict], exported_by: str | None,
) -> str:
    """A prose narrative covering everything else in this export -- meant
    to be read by a human during an audit, not machine-parsed (that's
    what manifest.json is for). See routes/export_routes.py's module
    docstring / the plan this shipped under for why this exists alongside
    the existing PDF report: report.pdf is a curated summary;
    this is the complete one."""
    name = engagement.get("name", "(unnamed)")
    client = engagement.get("client") or "(none recorded)"
    status = engagement.get("status", "unknown")
    scope = ", ".join(engagement.get("scope") or []) or "(none declared)"
    out_of_scope = ", ".join(engagement.get("out_of_scope") or []) or "(none declared)"
    start = engagement.get("start_date")
    end = engagement.get("end_date")

    lines = [
        f"# Export summary — {name}",
        "",
        f"Exported by **{exported_by or 'unknown'}** on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.",
        "",
        "## Engagement",
        "",
        f"- **Client:** {client}",
        f"- **Status:** {status}",
        f"- **Started:** {start}" + (f" — **ended:** {end}" if end else " (still open)"),
        f"- **In-scope targets:** {scope}",
        f"- **Explicitly out-of-scope:** {out_of_scope}",
        f"- **Description:** {engagement.get('description') or '(none)'}",
        "",
        "## Findings",
        "",
        f"{len(findings)} finding(s) recorded ({_severity_breakdown(findings)}).",
        "",
    ]
    notable = _notable_findings(findings)
    if notable:
        lines.append("The highest-severity findings, most severe first:")
        lines.append("")
        for f in notable:
            title = f.get("title", "(untitled)")
            sev = f.get("severity", "unknown")
            tool = f.get("tool", "")
            cve = f.get("cve_id")
            tag = f" (**{cve}**)" if cve else ""
            lines.append(f"- **[{sev}]** {title}{tag} — found by `{tool}`" if tool else f"- **[{sev}]** {title}{tag}")
        lines.append("")

    lines += [
        "## Assets and services",
        "",
        f"{len(asset_data.get('assets', []))} asset(s) tracked, "
        f"{len(asset_data.get('services', []))} service(s) recorded on them, "
        f"and {len(asset_data.get('findings', []))} finding(s) in the separate local "
        "asset-inventory store (asset_server's own findings table — distinct from the "
        "OpenSearch-backed findings above; see findings.json vs. assets.json).",
        "",
        "## Watchlist",
        "",
        f"{len(watchlist)} indicator(s) on the watchlist tied to this run.",
        "",
        "## Audit trail",
        "",
        f"{len(invocations)} tool invocation(s) recorded ({_audit_outcome_breakdown(invocations)}). "
        "Full command-line arguments and outcomes are in audit_log.json; each invocation's "
        "complete, unredacted tool output (where captured) is under raw_logs/, named "
        "`<invocation id>_<binary>.log`.",
        "",
        "## Timeline",
        "",
    ]
    if timeline:
        for ev in timeline[:30]:
            when = ev.get("ts")
            lines.append(f"- {when} — **[{ev.get('event_type', 'note')}]** {ev.get('summary', '')}")
        if len(timeline) > 30:
            lines.append(f"- … and {len(timeline) - 30} more event(s), see engagement.json.")
    else:
        lines.append("No timeline events recorded.")
    lines += [
        "",
        "## What's in this export",
        "",
        "- `engagement.json` — full engagement metadata + complete timeline",
        "- `findings.json` — every finding (OpenSearch-backed store)",
        "- `assets.json` — assets, services, and the separate local findings store",
        "- `watchlist.json` — IOC watchlist entries",
        "- `audit_log.json` — every toolchain invocation, structured",
        "- `raw_logs/` — each invocation's full, unredacted tool output",
        "- `report.pdf` — a shorter, curated summary (if generation succeeded)",
        "- `manifest.json` — machine-readable counts and export metadata",
    ]
    return "\n".join(lines)


def _build_all_summary_md(
    engagements: list[dict], findings: list[dict], asset_data: dict, watchlist: list[dict],
    invocations: list[dict], exported_by: str | None,
) -> str:
    lines = [
        "# Export summary — everything",
        "",
        f"Exported by **{exported_by or 'unknown'}** on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.",
        "",
        f"Covers **{len(engagements)} engagement(s)**, all time, every finding, "
        "every audit-trail entry, every rule, and every already-generated report.",
        "",
        "## Engagements",
        "",
    ]
    for eng in engagements:
        lines.append(f"- **{eng.get('name', '(unnamed)')}** ({eng.get('status', 'unknown')}) — client: {eng.get('client') or '(none)'}")
    lines += [
        "",
        "## Findings",
        "",
        f"{len(findings)} finding(s) across every engagement ({_severity_breakdown(findings)}).",
        "",
        "## Assets and services",
        "",
        f"{len(asset_data.get('assets', []))} asset(s), {len(asset_data.get('services', []))} service(s), "
        f"{len(asset_data.get('findings', []))} finding(s) in the separate local asset-inventory store.",
        "",
        "## Watchlist",
        "",
        f"{len(watchlist)} indicator(s) on the watchlist.",
        "",
        "## Audit trail",
        "",
        f"{len(invocations)} tool invocation(s) recorded ({_audit_outcome_breakdown(invocations)}).",
        "",
        "## What's in this export",
        "",
        "- `engagements.json` — every engagement, full metadata + timeline",
        "- `findings.json` — every finding (OpenSearch-backed store)",
        "- `assets.json` — assets, services, and the separate local findings store",
        "- `watchlist.json` — IOC watchlist entries",
        "- `audit_log.json` — every toolchain invocation, structured",
        "- `raw_logs/` — each invocation's full, unredacted tool output",
        "- `rules/` — every stored Sigma/YARA detection rule",
        "- `reports/` — every already-generated engagement report PDF",
        "- `manifest.json` — machine-readable counts and export metadata",
    ]
    return "\n".join(lines)


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


def _zip_response(buf: io.BytesIO, filename: str, passphrase: str = "") -> Response:
    """Encrypt the zip bytes if a passphrase was given (see
    encrypt_export_bytes above), and adjust the filename/media type so the
    result is never mistaken for a directly-openable .zip."""
    data = buf.getvalue()
    if passphrase:
        data = encrypt_export_bytes(data, passphrase)
        filename = filename.removesuffix(".zip") + ".chiron-export"
        media_type = "application/octet-stream"
    else:
        media_type = "application/zip"
    return Response(
        content=data,
        media_type=media_type,
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
        zf.writestr("SUMMARY.md", _build_engagement_summary_md(
            engagement, timeline, findings, asset_data, watchlist, invocations, exported_by,
        ))
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
        zf.writestr("SUMMARY.md", _build_all_summary_md(
            engagements, findings, asset_data, watchlist, invocations, exported_by,
        ))
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


# ---------------------------------------------------------------------------
# Wipe -- delete everything an export covers, once it's safely archived
# ---------------------------------------------------------------------------
#
# No MCP tool anywhere in this fork exposes bulk delete for
# engagements/findings/assets/watchlist -- this reads/writes each
# server's own underlying store directly (same duplicate-access pattern
# routes/security_dashboard_routes.py already establishes), deliberately
# NOT as a new MCP tool: "wipe my security data" is a UI-driven, always-
# confirmed action, not something that should be casually agent-callable.
# None of these tables have SQLite foreign-key cascade actually enforced
# (PRAGMA foreign_keys is off by default and none of these servers turn
# it on), so child rows (services, watchlist_checks, engagement_events)
# are deleted explicitly rather than relied on to cascade.

def _wipe_engagement_data(engagement_id: str) -> dict:
    """Best-effort per store -- one store failing (e.g. OpenSearch
    unreachable) must not stop the others from being wiped."""
    counts: dict[str, int] = {}

    try:
        import mcp_servers.findings_server as findings_mod
        resp = findings_mod._req(
            "POST", f"/{findings_mod._INDEX}/_delete_by_query",
            {"query": {"term": {"engagement": engagement_id}}},
        )
        counts["findings"] = resp.get("deleted", 0)
    except Exception:  # noqa: BLE001
        logger.warning("Wipe: failed to delete OpenSearch findings for %r", engagement_id, exc_info=True)

    try:
        import mcp_servers.asset_server as asset_mod
        conn = asset_mod._get_db()
        try:
            asset_ids = [r[0] for r in conn.execute(
                "SELECT id FROM assets WHERE engagement_id=?", (engagement_id,)).fetchall()]
            services_deleted = 0
            if asset_ids:
                placeholders = ",".join("?" * len(asset_ids))
                services_deleted = conn.execute(
                    f"DELETE FROM services WHERE asset_id IN ({placeholders})", asset_ids).rowcount
            counts["local_findings"] = conn.execute(
                "DELETE FROM findings WHERE engagement_id=?", (engagement_id,)).rowcount
            counts["assets"] = conn.execute(
                "DELETE FROM assets WHERE engagement_id=?", (engagement_id,)).rowcount
            counts["services"] = services_deleted
            conn.commit()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        logger.warning("Wipe: failed to delete assets/services for %r", engagement_id, exc_info=True)

    try:
        import mcp_servers.audit_server as audit_mod
        import mcp_servers.common as common_mod
        conn = audit_mod._get_db()
        try:
            rows = conn.execute(
                "SELECT raw_log_path FROM tool_invocations WHERE engagement_id=?", (engagement_id,)).fetchall()
            for (rel,) in rows:
                if rel:
                    try:
                        (common_mod._DATA_DIR / rel).unlink(missing_ok=True)
                    except OSError:
                        pass
            counts["audit_invocations"] = conn.execute(
                "DELETE FROM tool_invocations WHERE engagement_id=?", (engagement_id,)).rowcount
            conn.commit()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        logger.warning("Wipe: failed to delete audit trail for %r", engagement_id, exc_info=True)

    try:
        import mcp_servers.watchlist_server as watchlist_mod
        conn = watchlist_mod._get_db()
        try:
            wl_ids = [r[0] for r in conn.execute(
                "SELECT id FROM watchlist WHERE engagement_id=?", (engagement_id,)).fetchall()]
            if wl_ids:
                placeholders = ",".join("?" * len(wl_ids))
                conn.execute(f"DELETE FROM watchlist_checks WHERE watchlist_id IN ({placeholders})", wl_ids)
            counts["watchlist_entries"] = conn.execute(
                "DELETE FROM watchlist WHERE engagement_id=?", (engagement_id,)).rowcount
            conn.commit()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        logger.warning("Wipe: failed to delete watchlist entries for %r", engagement_id, exc_info=True)

    try:
        import mcp_servers.engagement_server as engagement_mod
        conn = engagement_mod._get_db()
        try:
            counts["timeline_events"] = conn.execute(
                "DELETE FROM engagement_events WHERE engagement_id=?", (engagement_id,)).rowcount
            counts["engagements"] = conn.execute(
                "DELETE FROM engagements WHERE id=?", (engagement_id,)).rowcount
            conn.commit()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        logger.warning("Wipe: failed to delete engagement %r", engagement_id, exc_info=True)

    return counts


def _wipe_all_data() -> dict:
    """Same as _wipe_engagement_data but unscoped -- every row in every
    table it touches, not filtered by engagement_id."""
    counts: dict[str, int] = {}

    try:
        import mcp_servers.findings_server as findings_mod
        resp = findings_mod._req(
            "POST", f"/{findings_mod._INDEX}/_delete_by_query", {"query": {"match_all": {}}},
        )
        counts["findings"] = resp.get("deleted", 0)
    except Exception:  # noqa: BLE001
        logger.warning("Wipe-all: failed to delete OpenSearch findings", exc_info=True)

    try:
        import mcp_servers.asset_server as asset_mod
        conn = asset_mod._get_db()
        try:
            counts["services"] = conn.execute("DELETE FROM services").rowcount
            counts["local_findings"] = conn.execute("DELETE FROM findings").rowcount
            counts["assets"] = conn.execute("DELETE FROM assets").rowcount
            conn.commit()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        logger.warning("Wipe-all: failed to delete assets/services", exc_info=True)

    try:
        import mcp_servers.audit_server as audit_mod
        import mcp_servers.common as common_mod
        conn = audit_mod._get_db()
        try:
            rows = conn.execute("SELECT raw_log_path FROM tool_invocations").fetchall()
            for (rel,) in rows:
                if rel:
                    try:
                        (common_mod._DATA_DIR / rel).unlink(missing_ok=True)
                    except OSError:
                        pass
            counts["audit_invocations"] = conn.execute("DELETE FROM tool_invocations").rowcount
            conn.commit()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        logger.warning("Wipe-all: failed to delete audit trail", exc_info=True)

    try:
        import mcp_servers.watchlist_server as watchlist_mod
        conn = watchlist_mod._get_db()
        try:
            conn.execute("DELETE FROM watchlist_checks")
            counts["watchlist_entries"] = conn.execute("DELETE FROM watchlist").rowcount
            conn.commit()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        logger.warning("Wipe-all: failed to delete watchlist entries", exc_info=True)

    try:
        import mcp_servers.engagement_server as engagement_mod
        conn = engagement_mod._get_db()
        try:
            counts["timeline_events"] = conn.execute("DELETE FROM engagement_events").rowcount
            counts["engagements"] = conn.execute("DELETE FROM engagements").rowcount
            conn.commit()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        logger.warning("Wipe-all: failed to delete engagements", exc_info=True)

    return counts


def setup_export_routes() -> APIRouter:
    @router.post("/engagement/{engagement_id}")
    async def export_engagement(request: Request, engagement_id: str, body: ExportRequestBody = ExportRequestBody()):
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
        response = _zip_response(buf, filename, body.passphrase)
        await _notify_export_complete(engagement_id=engagement_id, user=user)
        return response

    @router.post("/all")
    async def export_all(request: Request, body: ExportRequestBody = ExportRequestBody()):
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
        response = _zip_response(buf, filename, body.passphrase)
        await _notify_export_complete(engagement_id=None, user=user)
        return response

    @router.delete("/engagement/{engagement_id}")
    async def wipe_engagement(request: Request, engagement_id: str, confirm: bool = False):
        require_admin(request)
        if not confirm:
            raise HTTPException(400, "Pass confirm=true to wipe -- this is irreversible.")
        import mcp_servers.engagement_server as engagement_mod
        engagement = await asyncio.to_thread(engagement_mod._get_engagement, engagement_id)
        if engagement is None:
            raise HTTPException(404, f"No engagement with id {engagement_id!r}")
        counts = await asyncio.to_thread(_wipe_engagement_data, engagement_id)
        return {"wiped": True, "engagement_id": engagement_id, "counts": counts}

    @router.delete("/all")
    async def wipe_all(request: Request, confirm: bool = False):
        require_admin(request)
        if not confirm:
            raise HTTPException(400, "Pass confirm=true to wipe -- this is irreversible.")
        counts = await asyncio.to_thread(_wipe_all_data)
        return {"wiped": True, "scope": "all", "counts": counts}

    return router
