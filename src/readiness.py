"""Ithaca anchor — local-instance readiness / integrity self-check.

Beyond ``/api/health``'s liveness ping, this confirms the self-hosted instance is
whole and at home: the database is reachable, the data directory is present and
writable, and storage is local-first. Served by ``GET /api/ready`` and suitable
for an orchestrator readiness probe (200 only when every critical check passes).
"""

import os
import uuid
from datetime import datetime
from typing import Dict


def check_readiness() -> Dict[str, object]:
    """Run the readiness checks and return a JSON-serialisable report.

    ``ready`` is True only when every critical check (database, data_dir) passes.
    ``local_first`` is informational — a remote database is a valid deployment, so
    it never fails readiness, it only reports whether storage stays on this host.
    """
    from core.constants import APP_VERSION, DATA_DIR
    from core.database import DATABASE_URL, engine
    from sqlalchemy import text as sql_text

    checks: Dict[str, Dict[str, object]] = {}

    # Database reachable — the simplest honest probe that the engine is live.
    try:
        with engine.connect() as conn:
            conn.execute(sql_text("SELECT 1"))
        checks["database"] = {"ok": True}
    except Exception as e:
        checks["database"] = {"ok": False, "error": str(e)}

    # Data directory present and writable — home must be able to hold its own data.
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        probe = os.path.join(DATA_DIR, f".ready_probe_{uuid.uuid4().hex}")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.remove(probe)
        checks["data_dir"] = {"ok": True, "path": DATA_DIR}
    except Exception as e:
        checks["data_dir"] = {"ok": False, "error": str(e)}

    # Local-first: storage stays on the home machine (informational, never fatal).
    local_first = (
        DATABASE_URL.startswith("sqlite")
        or "localhost" in DATABASE_URL
        or "127.0.0.1" in DATABASE_URL
    )
    checks["local_first"] = {"ok": True, "local": local_first}

    # MCP servers — informational, never fatal to overall readiness (a
    # misconfigured or not-yet-connected optional MCP server doesn't mean
    # the instance itself is broken). Upstream has open reports of MCP
    # servers intermittently failing to register with tools silently
    # "disappearing" rather than raising a visible error; this surfaces
    # each configured server's actual connection status (populated by the
    # startup connection sweep in app.py) so a broken server shows up here
    # instead of only being discoverable by a user hitting a missing tool
    # mid-session. Snapshot-only: does not attempt new connections, so this
    # stays fast enough for a readiness probe hit on every health check.
    try:
        from src.tool_utils import get_mcp_manager

        manager = get_mcp_manager()
        statuses = manager.get_all_statuses() if manager else {}
        failed = {
            sid: s for sid, s in statuses.items()
            if s.get("status") not in ("connected", "needs_auth", "connecting")
        }
        checks["mcp_servers"] = {
            "ok": True,
            "configured": len(statuses),
            "connected": sum(1 for s in statuses.values() if s.get("status") == "connected"),
            "failed": {
                sid: {"name": s.get("name"), "status": s.get("status"), "error": s.get("error")}
                for sid, s in failed.items()
            },
        }
    except Exception as e:
        checks["mcp_servers"] = {"ok": True, "error": f"status unavailable: {e}"}

    ready = all(bool(c.get("ok")) for c in checks.values())
    return {
        "ready": ready,
        "version": APP_VERSION,
        "checks": checks,
        "timestamp": datetime.utcnow().isoformat(),
    }
