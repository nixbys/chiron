"""
monitor_server.py

MCP server backing continuous/scheduled scanning: stores the last known
"snapshot" of a recurring check (open ports, subdomains, TLS cert, known
CVEs) per (task_id, target, check_type), and records a diff whenever a
snapshot changes. The scheduled action that actually runs the scans
(src/builtin_actions.py's action_scheduled_recon) imports this module's
private functions directly rather than going through the MCP text-tool
interface, so it can compare structured data run-to-run.

This server's own tools are for introspection/chat access only (viewing
current state, diff history, or forcing a re-baseline) -- the scheduled
scan path itself never calls call_tool().
"""

import asyncio
import hashlib
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import mcp_error

server = Server("monitor")

_DATA_DIR = Path(os.environ.get("ODYSSEUS_DATA_DIR", "./data"))
_DB_PATH = _DATA_DIR / "monitor.db"

_CHECK_TYPES = ("ports", "subdomains", "cert", "cve")

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
            CREATE TABLE IF NOT EXISTS monitor_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                owner TEXT,
                target TEXT NOT NULL,
                check_type TEXT NOT NULL,
                engagement_id TEXT,
                snapshot TEXT NOT NULL,
                snapshot_hash TEXT NOT NULL,
                last_run REAL NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE(task_id, target, check_type)
            );

            CREATE TABLE IF NOT EXISTS monitor_diffs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                target TEXT NOT NULL,
                check_type TEXT NOT NULL,
                added TEXT DEFAULT '[]',
                removed TEXT DEFAULT '[]',
                ts REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_monitor_state_task ON monitor_state(task_id);
            CREATE INDEX IF NOT EXISTS idx_monitor_diffs_task ON monitor_diffs(task_id);
        """)


def _hash_snapshot(snapshot: dict) -> str:
    canonical = json.dumps(snapshot, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _get_snapshot(task_id: str, target: str, check_type: str) -> dict | None:
    """Return the last stored snapshot dict for this check, or None if this
    is the first run (no baseline yet)."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT snapshot FROM monitor_state WHERE task_id=? AND target=? AND check_type=?",
            (task_id, target, check_type),
        ).fetchone()
        return json.loads(row["snapshot"]) if row else None
    finally:
        conn.close()


def _save_snapshot(task_id: str, owner: str, target: str, check_type: str,
                    engagement_id: str | None, snapshot: dict) -> None:
    conn = _get_db()
    now = time.time()
    try:
        conn.execute("""
            INSERT INTO monitor_state (task_id, owner, target, check_type, engagement_id, snapshot, snapshot_hash, last_run, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(task_id, target, check_type) DO UPDATE SET
                snapshot=excluded.snapshot, snapshot_hash=excluded.snapshot_hash,
                last_run=excluded.last_run, engagement_id=COALESCE(excluded.engagement_id, monitor_state.engagement_id)
        """, (task_id, owner, target, check_type, engagement_id,
              json.dumps(snapshot), _hash_snapshot(snapshot), now, now))
        conn.commit()
    finally:
        conn.close()


def _compute_diff(old: dict | None, new: dict) -> tuple[list, list]:
    """Compare two snapshots' "items" lists (e.g. open ports, subdomains,
    CVE ids) and return (added, removed). A snapshot with no baseline
    (old is None) is treated as having nothing to diff against -- the
    caller should record this run as the baseline without filing findings."""
    old_items = set(old.get("items", [])) if old else set()
    new_items = set(new.get("items", []))
    added = sorted(new_items - old_items)
    removed = sorted(old_items - new_items)
    return added, removed


def _record_diff(task_id: str, target: str, check_type: str, added: list, removed: list) -> None:
    conn = _get_db()
    try:
        conn.execute(
            "INSERT INTO monitor_diffs (task_id, target, check_type, added, removed, ts) VALUES (?, ?, ?, ?, ?, ?)",
            (task_id, target, check_type, json.dumps(added), json.dumps(removed), time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def _list_recent_diffs(limit: int = 20) -> list[dict]:
    """All-tasks variant of monitor_diff_history's per-task query -- for
    direct import by the security dashboard route (routes/
    security_dashboard_routes.py), which needs "what drifted recently"
    across every scheduled scan, not just one task."""
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT task_id, target, check_type, added, removed, ts FROM monitor_diffs ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


TOOLS = [
    Tool(
        name="monitor_list_tasks",
        description="List all (task_id, target, check_type) combinations currently being monitored, with their last run time.",
        inputSchema={"type": "object", "properties": {"limit": {"type": "integer", "default": 50}}},
    ),
    Tool(
        name="monitor_get_state",
        description="Get the current stored snapshot for one monitored check.",
        inputSchema={
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "target": {"type": "string"},
                "check_type": {"type": "string", "enum": list(_CHECK_TYPES)},
            },
            "required": ["task_id", "target", "check_type"],
        },
    ),
    Tool(
        name="monitor_diff_history",
        description="List recent drift events (added/removed items) recorded for a scheduled scan task.",
        inputSchema={
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
            },
            "required": ["task_id"],
        },
    ),
    Tool(
        name="monitor_reset",
        description="Clear a stored snapshot so the next scheduled run re-baselines instead of reporting drift (use after a known/expected infra change).",
        inputSchema={
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "target": {"type": "string", "description": "Omit to reset all targets for this task"},
                "check_type": {"type": "string", "enum": list(_CHECK_TYPES), "description": "Omit to reset all check types"},
            },
            "required": ["task_id"],
        },
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        conn = _get_db()

        if name == "monitor_list_tasks":
            rows = conn.execute(
                "SELECT task_id, target, check_type, last_run FROM monitor_state ORDER BY last_run DESC LIMIT ?",
                (arguments.get("limit", 50),),
            ).fetchall()
            if not rows:
                result = "No monitored checks yet."
            else:
                lines = [f"{'Task ID':<38} {'Target':<24} {'Check':<12} Last run"]
                lines.append("-" * 100)
                for r in rows:
                    stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["last_run"]))
                    lines.append(f"{r['task_id']:<38} {r['target']:<24} {r['check_type']:<12} {stamp}")
                result = "\n".join(lines)

        elif name == "monitor_get_state":
            row = conn.execute(
                "SELECT snapshot, last_run FROM monitor_state WHERE task_id=? AND target=? AND check_type=?",
                (arguments["task_id"], arguments["target"], arguments["check_type"]),
            ).fetchone()
            if not row:
                result = "No stored snapshot for this check yet."
            else:
                stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["last_run"]))
                result = f"Last run: {stamp}\nSnapshot: {row['snapshot']}"

        elif name == "monitor_diff_history":
            rows = conn.execute(
                "SELECT target, check_type, added, removed, ts FROM monitor_diffs WHERE task_id=? ORDER BY ts DESC LIMIT ?",
                (arguments["task_id"], arguments.get("limit", 20)),
            ).fetchall()
            if not rows:
                result = "No drift recorded for this task yet."
            else:
                lines = []
                for r in rows:
                    stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["ts"]))
                    added = json.loads(r["added"] or "[]")
                    removed = json.loads(r["removed"] or "[]")
                    lines.append(f"- {stamp} [{r['check_type']}] {r['target']}: +{added} -{removed}")
                result = "\n".join(lines)

        elif name == "monitor_reset":
            query = "DELETE FROM monitor_state WHERE task_id=?"
            params: list = [arguments["task_id"]]
            if target := arguments.get("target"):
                query += " AND target=?"
                params.append(target)
            if check_type := arguments.get("check_type"):
                query += " AND check_type=?"
                params.append(check_type)
            cur = conn.execute(query, params)
            conn.commit()
            result = f"Cleared {cur.rowcount} stored snapshot(s); next run(s) will re-baseline."

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
