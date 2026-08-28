"""
engagement_server.py

MCP server for grouping recon/scan/watchlist findings under a named
engagement (case, pentest, incident). Stores engagements and their event
timeline in a local SQLite database inside the Odysseus data directory.

Other MCP servers (asset_server, findings_server, monitor_server,
watchlist_server) never import this module directly -- each MCP server in
this fork is a standalone subprocess. Instead, `engagement_id` (the id
returned by `engagement_create`) is threaded through as a plain string
field/tag on those servers' own tools (asset_server's `engagement_id`
column, findings_server's `engagement` keyword field), and
`engagement_log_event` is called by whatever orchestrates a scan (a skill,
or a scheduled `action_*` function) to build the timeline consumed by
`engagement_timeline` for reporting.
"""

import asyncio
import json
import os
import sqlite3
import sys
import time
import uuid
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import mcp_error

server = Server("engagements")

_DATA_DIR = Path(os.environ.get("ODYSSEUS_DATA_DIR", "./data"))
_DB_PATH = _DATA_DIR / "engagements.db"

_STATUSES = ("active", "paused", "closed")
_EVENT_TYPES = ("scan_started", "scan_completed", "finding_added", "watchlist_hit", "note")

_db_initialized = False


def _get_db() -> sqlite3.Connection:
    global _db_initialized
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    if not _db_initialized:
        # Lazy schema init -- see asset_server.py's _get_db for why this is
        # deferred past module import time (a missing/unwritable data dir
        # must not crash tool *registration*).
        _init_db(conn)
        _db_initialized = True
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS engagements (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT DEFAULT '',
                client TEXT DEFAULT '',
                scope TEXT DEFAULT '[]',
                out_of_scope TEXT DEFAULT '[]',
                status TEXT DEFAULT 'active',
                start_date REAL,
                end_date REAL,
                tags TEXT DEFAULT '[]',
                created_at REAL,
                updated_at REAL
            );

            CREATE TABLE IF NOT EXISTS engagement_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT REFERENCES engagements(id) ON DELETE CASCADE,
                event_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                detail TEXT DEFAULT '',
                ts REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_engagement_events_eng ON engagement_events(engagement_id);
            CREATE INDEX IF NOT EXISTS idx_engagements_status ON engagements(status);
        """)


def _get_engagement(engagement_id: str) -> dict | None:
    """Return an engagement row as a dict, or None. For direct import by
    other in-process code (e.g. src/builtin_actions.py's scheduled security
    actions) that needs to validate/enrich an engagement_id without going
    through the MCP text-tool interface."""
    conn = _get_db()
    try:
        row = conn.execute("SELECT * FROM engagements WHERE id=?", (engagement_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _log_event(engagement_id: str, event_type: str, summary: str, detail: str = "") -> None:
    """Append a timeline event. Silently no-ops if the engagement doesn't
    exist, since callers (scheduled scans, watchlist checks) treat
    engagement_id as an optional tag, not a hard requirement."""
    if not engagement_id:
        return
    conn = _get_db()
    try:
        if not conn.execute("SELECT 1 FROM engagements WHERE id=?", (engagement_id,)).fetchone():
            return
        conn.execute(
            "INSERT INTO engagement_events (engagement_id, event_type, summary, detail, ts) VALUES (?, ?, ?, ?, ?)",
            (engagement_id, event_type, summary, detail, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


TOOLS = [
    Tool(
        name="engagement_create",
        description="Create a new engagement (pentest, red-team op, incident) to group assets, findings, and scan activity under.",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Unique short name, e.g. 'acme-q3-pentest'"},
                "description": {"type": "string", "default": ""},
                "client": {"type": "string", "default": ""},
                "scope": {"type": "array", "items": {"type": "string"}, "description": "In-scope targets/CIDRs/domains", "default": []},
                "out_of_scope": {"type": "array", "items": {"type": "string"}, "default": []},
                "tags": {"type": "array", "items": {"type": "string"}, "default": []},
            },
            "required": ["name"],
        },
    ),
    Tool(
        name="engagement_list",
        description="List engagements, optionally filtered by status.",
        inputSchema={
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": list(_STATUSES)},
                "limit": {"type": "integer", "default": 50},
            },
        },
    ),
    Tool(
        name="engagement_get",
        description="Get full details of one engagement, including its recent timeline.",
        inputSchema={
            "type": "object",
            "properties": {"engagement_id": {"type": "string"}},
            "required": ["engagement_id"],
        },
    ),
    Tool(
        name="engagement_update",
        description="Update an engagement's description, client, scope, or tags.",
        inputSchema={
            "type": "object",
            "properties": {
                "engagement_id": {"type": "string"},
                "description": {"type": "string"},
                "client": {"type": "string"},
                "scope": {"type": "array", "items": {"type": "string"}},
                "out_of_scope": {"type": "array", "items": {"type": "string"}},
                "tags": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["engagement_id"],
        },
    ),
    Tool(
        name="engagement_close",
        description="Mark an engagement closed and record its end date.",
        inputSchema={
            "type": "object",
            "properties": {"engagement_id": {"type": "string"}},
            "required": ["engagement_id"],
        },
    ),
    Tool(
        name="engagement_log_event",
        description="Append an event to an engagement's timeline (scan started/completed, finding added, watchlist hit, note). Used to build the report timeline.",
        inputSchema={
            "type": "object",
            "properties": {
                "engagement_id": {"type": "string"},
                "event_type": {"type": "string", "enum": list(_EVENT_TYPES)},
                "summary": {"type": "string"},
                "detail": {"type": "string", "default": ""},
            },
            "required": ["engagement_id", "event_type", "summary"],
        },
    ),
    Tool(
        name="engagement_timeline",
        description="Return the chronological event timeline for an engagement, for use in a report.",
        inputSchema={
            "type": "object",
            "properties": {
                "engagement_id": {"type": "string"},
                "limit": {"type": "integer", "default": 200},
            },
            "required": ["engagement_id"],
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

        if name == "engagement_create":
            engagement_id = uuid.uuid4().hex
            try:
                conn.execute("""
                    INSERT INTO engagements
                        (id, name, description, client, scope, out_of_scope, status, start_date, tags, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
                """, (
                    engagement_id, arguments["name"], arguments.get("description", ""),
                    arguments.get("client", ""), json.dumps(arguments.get("scope", [])),
                    json.dumps(arguments.get("out_of_scope", [])), now,
                    json.dumps(arguments.get("tags", [])), now, now,
                ))
                conn.commit()
                result = f"Engagement '{arguments['name']}' created (id={engagement_id})."
            except sqlite3.IntegrityError:
                result = mcp_error("duplicate", f"An engagement named {arguments['name']!r} already exists.")

        elif name == "engagement_list":
            query = "SELECT id, name, client, status, start_date, end_date FROM engagements WHERE 1=1"
            params: list = []
            if status := arguments.get("status"):
                query += " AND status=?"
                params.append(status)
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(arguments.get("limit", 50))
            rows = conn.execute(query, params).fetchall()
            if not rows:
                result = "No engagements found."
            else:
                lines = [f"{'ID':<34} {'Name':<24} {'Client':<16} {'Status':<8}"]
                lines.append("-" * 90)
                for r in rows:
                    lines.append(f"{r['id']:<34} {r['name']:<24} {r['client'] or '':<16} {r['status']:<8}")
                result = "\n".join(lines)

        elif name == "engagement_get":
            row = conn.execute("SELECT * FROM engagements WHERE id=?", (arguments["engagement_id"],)).fetchone()
            if not row:
                result = mcp_error("not_found", f"No engagement with id {arguments['engagement_id']!r}")
            else:
                events = conn.execute(
                    "SELECT event_type, summary, ts FROM engagement_events WHERE engagement_id=? ORDER BY ts DESC LIMIT 20",
                    (arguments["engagement_id"],),
                ).fetchall()
                event_lines = "\n".join(f"  [{e['event_type']}] {e['summary']}" for e in events) or "  (none yet)"
                result = (
                    f"{row['name']} ({row['status']})\n"
                    f"Client: {row['client'] or '(none)'}\n"
                    f"Description: {row['description'] or '(none)'}\n"
                    f"Scope: {', '.join(json.loads(row['scope'] or '[]')) or '(none)'}\n"
                    f"Out of scope: {', '.join(json.loads(row['out_of_scope'] or '[]')) or '(none)'}\n"
                    f"Tags: {', '.join(json.loads(row['tags'] or '[]')) or '(none)'}\n"
                    f"Recent events:\n{event_lines}"
                )

        elif name == "engagement_update":
            engagement_id = arguments["engagement_id"]
            if not conn.execute("SELECT 1 FROM engagements WHERE id=?", (engagement_id,)).fetchone():
                result = mcp_error("not_found", f"No engagement with id {engagement_id!r}")
            else:
                fields, params = [], []
                for key in ("description", "client"):
                    if key in arguments:
                        fields.append(f"{key}=?")
                        params.append(arguments[key])
                for key in ("scope", "out_of_scope", "tags"):
                    if key in arguments:
                        fields.append(f"{key}=?")
                        params.append(json.dumps(arguments[key]))
                if fields:
                    fields.append("updated_at=?")
                    params.append(now)
                    params.append(engagement_id)
                    # nosec B608 -- `fields` only ever contains column names
                    # from the fixed whitelist above (never arguments["..."]
                    # keys), so this isn't string-built from untrusted input;
                    # all actual values are still bound as `?` params.
                    conn.execute(f"UPDATE engagements SET {', '.join(fields)} WHERE id=?", params)  # nosec B608
                    conn.commit()
                result = f"Engagement {engagement_id} updated."

        elif name == "engagement_close":
            engagement_id = arguments["engagement_id"]
            cur = conn.execute(
                "UPDATE engagements SET status='closed', end_date=?, updated_at=? WHERE id=?",
                (now, now, engagement_id),
            )
            conn.commit()
            if cur.rowcount == 0:
                result = mcp_error("not_found", f"No engagement with id {engagement_id!r}")
            else:
                result = f"Engagement {engagement_id} closed."

        elif name == "engagement_log_event":
            engagement_id = arguments["engagement_id"]
            if not conn.execute("SELECT 1 FROM engagements WHERE id=?", (engagement_id,)).fetchone():
                result = mcp_error("not_found", f"No engagement with id {engagement_id!r}")
            else:
                conn.execute(
                    "INSERT INTO engagement_events (engagement_id, event_type, summary, detail, ts) VALUES (?, ?, ?, ?, ?)",
                    (engagement_id, arguments["event_type"], arguments["summary"], arguments.get("detail", ""), now),
                )
                conn.commit()
                result = "Event logged."

        elif name == "engagement_timeline":
            rows = conn.execute(
                "SELECT event_type, summary, detail, ts FROM engagement_events WHERE engagement_id=? ORDER BY ts ASC LIMIT ?",
                (arguments["engagement_id"], arguments.get("limit", 200)),
            ).fetchall()
            if not rows:
                result = "No events recorded for this engagement."
            else:
                lines = []
                for r in rows:
                    stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["ts"]))
                    lines.append(f"- {stamp} [{r['event_type']}] {r['summary']}")
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
