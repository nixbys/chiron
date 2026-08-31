"""
watchlist_server.py

MCP server for a persistent IOC watchlist: IPs, domains, hashes, and URLs
you want re-checked against threat-intel providers on a schedule, with a
finding filed only when something changes since the last check.

The scheduled re-check itself (src/builtin_actions.py's
action_watchlist_check) imports this module's private functions directly
and calls mcp_servers/intel_server.py's raw `_X_fetch()` functions to get
structured, diffable data -- it never goes through this server's own
call_tool() text interface.
"""

import asyncio
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import (
    SCOPE_ARG_PROPERTIES,
    check_scope_from_args,
    mcp_error,
    validate_domain,
    validate_ip,
    validate_url,
)

server = Server("watchlist")

_DATA_DIR = Path(os.environ.get("ODYSSEUS_DATA_DIR", "./data"))
_DB_PATH = _DATA_DIR / "watchlist.db"

_KINDS = ("ip", "domain", "hash", "url")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$")

_db_initialized = False


def _get_db() -> sqlite3.Connection:
    global _db_initialized
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    if not _db_initialized:
        # Lazy schema init -- see asset_server.py's _get_db for why this is
        # deferred past module import time.
        _init_db(conn)
        _db_initialized = True
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS watchlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                kind TEXT NOT NULL,
                engagement_id TEXT,
                source TEXT DEFAULT 'manual',
                notes TEXT DEFAULT '',
                status TEXT DEFAULT 'active',
                created_at REAL,
                UNIQUE(indicator, kind)
            );

            CREATE TABLE IF NOT EXISTS watchlist_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                watchlist_id INTEGER REFERENCES watchlist(id) ON DELETE CASCADE,
                provider TEXT NOT NULL,
                snapshot_hash TEXT NOT NULL,
                snapshot TEXT NOT NULL,
                checked_at REAL NOT NULL,
                UNIQUE(watchlist_id, provider)
            );

            CREATE INDEX IF NOT EXISTS idx_watchlist_checks_wid ON watchlist_checks(watchlist_id);
            CREATE INDEX IF NOT EXISTS idx_watchlist_status ON watchlist(status);
        """)


def _validate_indicator(indicator: str, kind: str) -> str | None:
    """Return None if valid for the given kind, or an mcp_error string."""
    if kind == "ip":
        return validate_ip(indicator)
    if kind == "domain":
        return validate_domain(indicator)
    if kind == "url":
        return validate_url(indicator)
    if kind == "hash":
        if not _HASH_RE.match(indicator):
            return mcp_error("invalid_hash", f"{indicator!r} is not a valid MD5/SHA1/SHA256/SHA512 hex hash")
        return None
    return mcp_error("invalid_kind", f"Unknown indicator kind: {kind}")


def _list_active_watchlist() -> list[dict]:
    """Return every active watchlist entry, for direct import by the
    scheduled watchlist-check action."""
    conn = _get_db()
    try:
        rows = conn.execute("SELECT * FROM watchlist WHERE status='active'").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _list_watchlist(kind: str | None = None, engagement_id: str | None = None, status: str = "active") -> list[dict]:
    """Structured (not text-table) entry list, for direct import by the
    security dashboard's watchlist-management route. `_list_active_watchlist`
    above stays as-is (status='active' only, no other filters) since the
    scheduled watchlist-check action already depends on that exact shape."""
    conn = _get_db()
    try:
        query = "SELECT id, indicator, kind, engagement_id, status, source, notes, created_at FROM watchlist WHERE 1=1"
        params: list = []
        if kind:
            query += " AND kind=?"
            params.append(kind)
        if engagement_id:
            query += " AND engagement_id=?"
            params.append(engagement_id)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY id DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _list_checks(watchlist_id: int) -> list[dict]:
    """Structured check history for one entry, for direct import by the
    security dashboard's watchlist-detail route."""
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT provider, snapshot, checked_at FROM watchlist_checks WHERE watchlist_id=? ORDER BY checked_at DESC",
            (watchlist_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _hash_snapshot(snapshot: dict) -> str:
    canonical = json.dumps(snapshot, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _get_last_check(watchlist_id: int, provider: str) -> dict | None:
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT snapshot, snapshot_hash FROM watchlist_checks WHERE watchlist_id=? AND provider=?",
            (watchlist_id, provider),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _save_check(watchlist_id: int, provider: str, snapshot: dict) -> None:
    conn = _get_db()
    try:
        conn.execute("""
            INSERT INTO watchlist_checks (watchlist_id, provider, snapshot_hash, snapshot, checked_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(watchlist_id, provider) DO UPDATE SET
                snapshot_hash=excluded.snapshot_hash, snapshot=excluded.snapshot, checked_at=excluded.checked_at
        """, (watchlist_id, provider, _hash_snapshot(snapshot), json.dumps(snapshot), time.time()))
        conn.commit()
    finally:
        conn.close()


TOOLS = [
    Tool(
        name="watchlist_add",
        description="Add an indicator (IP, domain, hash, or URL) to the persistent watchlist for scheduled re-checking against threat-intel providers.",
        inputSchema={
            "type": "object",
            "properties": {
                "indicator": {"type": "string"},
                "kind": {"type": "string", "enum": list(_KINDS)},
                "notes": {"type": "string", "default": ""},
                "source": {"type": "string", "default": "manual"},
                **SCOPE_ARG_PROPERTIES,
            },
            "required": ["indicator", "kind"],
        },
    ),
    Tool(
        name="watchlist_list",
        description="List watchlist entries, optionally filtered by kind, engagement, or status.",
        inputSchema={
            "type": "object",
            "properties": {
                "kind": {"type": "string", "enum": list(_KINDS)},
                "engagement_id": {"type": "string"},
                "status": {"type": "string", "enum": ["active", "paused"], "default": "active"},
            },
        },
    ),
    Tool(
        name="watchlist_remove",
        description="Remove an entry from the watchlist permanently.",
        inputSchema={
            "type": "object",
            "properties": {"watchlist_id": {"type": "integer"}},
            "required": ["watchlist_id"],
        },
    ),
    Tool(
        name="watchlist_pause",
        description="Pause an entry so scheduled checks skip it without deleting its history.",
        inputSchema={
            "type": "object",
            "properties": {"watchlist_id": {"type": "integer"}},
            "required": ["watchlist_id"],
        },
    ),
    Tool(
        name="watchlist_resume",
        description="Resume a paused watchlist entry.",
        inputSchema={
            "type": "object",
            "properties": {"watchlist_id": {"type": "integer"}},
            "required": ["watchlist_id"],
        },
    ),
    Tool(
        name="watchlist_check_history",
        description="Show each provider's last-checked snapshot for one watchlist entry.",
        inputSchema={
            "type": "object",
            "properties": {"watchlist_id": {"type": "integer"}},
            "required": ["watchlist_id"],
        },
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:  # noqa: C901
    now = time.time()
    try:
        conn = _get_db()

        if name == "watchlist_add":
            indicator = arguments["indicator"]
            kind = arguments["kind"]
            if err := _validate_indicator(indicator, kind):
                result = err
            elif kind in ("ip", "domain", "url") and (err := check_scope_from_args(arguments, indicator, "watchlist_add")):
                result = err
            else:
                try:
                    conn.execute("""
                        INSERT INTO watchlist (indicator, kind, engagement_id, source, notes, status, created_at)
                        VALUES (?, ?, ?, ?, ?, 'active', ?)
                    """, (indicator, kind, arguments.get("engagement_id"),
                          arguments.get("source", "manual"), arguments.get("notes", ""), now))
                    conn.commit()
                    result = f"Added {indicator} ({kind}) to the watchlist."
                except sqlite3.IntegrityError:
                    result = mcp_error("duplicate", f"{indicator!r} ({kind}) is already on the watchlist.")

        elif name == "watchlist_list":
            rows = _list_watchlist(
                kind=arguments.get("kind"),
                engagement_id=arguments.get("engagement_id"),
                status=arguments.get("status", "active"),
            )
            if not rows:
                result = "No watchlist entries found."
            else:
                lines = [f"{'ID':<6} {'Indicator':<40} {'Kind':<8} {'Status':<8} Source"]
                lines.append("-" * 90)
                for r in rows:
                    lines.append(f"{r['id']:<6} {r['indicator']:<40} {r['kind']:<8} {r['status']:<8} {r['source']}")
                result = "\n".join(lines)

        elif name == "watchlist_remove":
            cur = conn.execute("DELETE FROM watchlist WHERE id=?", (arguments["watchlist_id"],))
            conn.commit()
            result = f"Removed watchlist entry {arguments['watchlist_id']}." if cur.rowcount else mcp_error("not_found", f"No watchlist entry {arguments['watchlist_id']}")

        elif name == "watchlist_pause":
            cur = conn.execute("UPDATE watchlist SET status='paused' WHERE id=?", (arguments["watchlist_id"],))
            conn.commit()
            result = f"Paused watchlist entry {arguments['watchlist_id']}." if cur.rowcount else mcp_error("not_found", f"No watchlist entry {arguments['watchlist_id']}")

        elif name == "watchlist_resume":
            cur = conn.execute("UPDATE watchlist SET status='active' WHERE id=?", (arguments["watchlist_id"],))
            conn.commit()
            result = f"Resumed watchlist entry {arguments['watchlist_id']}." if cur.rowcount else mcp_error("not_found", f"No watchlist entry {arguments['watchlist_id']}")

        elif name == "watchlist_check_history":
            rows = _list_checks(arguments["watchlist_id"])
            if not rows:
                result = "No checks recorded yet for this entry."
            else:
                lines = []
                for r in rows:
                    stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["checked_at"]))
                    lines.append(f"- {r['provider']} @ {stamp}: {r['snapshot']}")
                result = "\n".join(lines)

        else:
            result = mcp_error("unknown_tool", name)

        conn.close()

    except Exception as exc:  # noqa: BLE001
        result = mcp_error("db_error", str(exc))

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
