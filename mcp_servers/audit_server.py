"""
audit_server.py

Read-only MCP server over the toolchain invocation audit trail that
mcp_servers/common.py's exec_in_toolchain() writes to on every single call
(see that module's "_log_invocation"/"_check_rate_limit" for the write
side and the rate-limit check that shares the same table). Findings
persistence (findings_server.py) already covers *results* -- this covers
*actions*: what actually ran, against what, when, and how it turned out.

Duplicates common.py's own audit.db connection logic rather than importing
it -- MCP servers in this fork are standalone subprocesses and never
import each other (common.py is a shared *utility* module, not an MCP
server, so it's the one thing every server already imports directly; this
server just happens to read the same SQLite file that utility writes to).
"""

import asyncio
import json
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import mcp_error, _CHAIN_GENESIS, _compute_row_hash

server = Server("audit")

_DATA_DIR = Path(os.environ.get("ODYSSEUS_DATA_DIR", "./data"))
_DB_PATH = _DATA_DIR / "audit.db"

_OUTCOMES = ("ok", "error", "timeout", "rate_limited", "blocked_out_of_scope", "scope_override")

_db_initialized = False
# Guards the check-and-set on _db_initialized below -- without it, several
# threads hitting _get_db() concurrently on a brand-new audit.db can all
# see _db_initialized == False and each run the CREATE TABLE/ALTER TABLE
# block itself; CREATE TABLE IF NOT EXISTS tolerates that, but ALTER TABLE
# ADD COLUMN does not ("duplicate column name") once a second migration
# joined the first (see test_concurrent_first_access_does_not_deadlock).
_db_init_lock = threading.Lock()


def _new_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _get_db() -> sqlite3.Connection:
    global _db_initialized
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not _db_initialized:
        with _db_init_lock:
            if not _db_initialized:
                # The connection used for schema setup is opened *inside*
                # the lock, after the double-checked flag -- not before it.
                # An earlier version opened every thread's connection
                # unconditionally up front, so on a brand-new audit.db
                # several already-open (idle) connections could coexist
                # with the one running ALTER TABLE, and SQLite's schema
                # lock requirements for DDL turned that into a real,
                # reproducible "database is locked" (not the "duplicate
                # column name" this lock alone already fixed) --
                # see test_concurrent_first_access_does_not_deadlock.
                # Serializing connection creation itself for the *first*
                # caller means no other connection exists yet while DDL
                # runs.
                conn = _new_connection()
                # Same table common.py's _get_audit_db() creates -- CREATE TABLE IF
                # NOT EXISTS here too so this server works standalone (e.g. before
                # any tool has ever run yet) rather than assuming common.py's
                # process created the file first.
                with conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS tool_invocations (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ts REAL NOT NULL,
                            binary TEXT NOT NULL,
                            args TEXT NOT NULL,
                            mode TEXT NOT NULL,
                            duration_ms INTEGER,
                            outcome TEXT NOT NULL,
                            detail TEXT DEFAULT '',
                            engagement_id TEXT
                        );
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_invocations_binary_ts ON tool_invocations(binary, ts);")
                    # Same migration guard as common.py's _get_audit_db() -- this
                    # server may be the first process to open audit.db.
                    cols = [r[1] for r in conn.execute("PRAGMA table_info(tool_invocations)").fetchall()]
                    if "engagement_id" not in cols:
                        conn.execute("ALTER TABLE tool_invocations ADD COLUMN engagement_id TEXT")
                    if "raw_log_path" not in cols:
                        conn.execute("ALTER TABLE tool_invocations ADD COLUMN raw_log_path TEXT")
                    if "row_hash" not in cols:
                        conn.execute("ALTER TABLE tool_invocations ADD COLUMN row_hash TEXT")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_invocations_engagement ON tool_invocations(engagement_id);")
                    # Checkpoint state for the scope_violation_check scheduled
                    # action (src/builtin_actions.py) -- "how far into
                    # tool_invocations has this task already reminded about",
                    # same (task_id -> state) shape as monitor_server.py's
                    # monitor_state table, just one row per task instead of one
                    # per (task_id, target, check_type).
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS audit_checkpoints (
                            task_id TEXT PRIMARY KEY,
                            last_id INTEGER NOT NULL DEFAULT 0,
                            updated_at REAL
                        );
                    """)
                _db_initialized = True
                return conn
    return _new_connection()


def _get_checkpoint(task_id: str) -> int:
    """Highest tool_invocations.id this task has already reminded about,
    or 0 if it has never run (the caller then treats *every* existing
    violation as new -- see action_scope_violation_check's own baseline
    handling for why that's deliberately guarded against there, not
    here)."""
    conn = _get_db()
    try:
        row = conn.execute("SELECT last_id FROM audit_checkpoints WHERE task_id=?", (task_id,)).fetchone()
        return row["last_id"] if row else 0
    finally:
        conn.close()


def _save_checkpoint(task_id: str, last_id: int) -> None:
    conn = _get_db()
    try:
        conn.execute(
            "INSERT INTO audit_checkpoints (task_id, last_id, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(task_id) DO UPDATE SET last_id=excluded.last_id, updated_at=excluded.updated_at",
            (task_id, last_id, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


_SCOPE_VIOLATION_OUTCOMES = ("blocked_out_of_scope", "scope_override")


def _list_scope_violations_since(after_id: int, engagement_id: str | None = None, limit: int = 200) -> list[dict]:
    """Scope-enforcement rows (mcp_servers/common.py's check_scope()) with
    id > after_id, oldest first -- for action_scope_violation_check
    (src/builtin_actions.py) to summarize into one reminder per run."""
    conn = _get_db()
    try:
        query = (
            "SELECT id, ts, binary, args, outcome, detail, engagement_id FROM tool_invocations "
            "WHERE id>? AND outcome IN (?, ?)"
        )
        params: list = [after_id, *_SCOPE_VIOLATION_OUTCOMES]
        if engagement_id:
            query += " AND engagement_id=?"
            params.append(engagement_id)
        query += " ORDER BY id ASC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["args"] = json.loads(d["args"])
            except (json.JSONDecodeError, TypeError):
                pass
            out.append(d)
        return out
    finally:
        conn.close()


def _count_scope_violations_in_window(engagement_id: str, window_s: float) -> int:
    """Rolling count of this engagement's blocked_out_of_scope/
    scope_override rows in the trailing `window_s` seconds -- for
    action_scope_violation_check (src/builtin_actions.py, Phase J) to
    detect a *pattern* of violations crossing an escalation threshold,
    independent of the checkpoint-based "new since last poll" count
    _list_scope_violations_since returns."""
    conn = _get_db()
    try:
        since = time.time() - window_s
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM tool_invocations "
            "WHERE engagement_id=? AND ts>? AND outcome IN (?, ?)",
            (engagement_id, since, *_SCOPE_VIOLATION_OUTCOMES),
        ).fetchone()
        return row["n"] if row else 0
    finally:
        conn.close()


def _list_invocations(
    binary: str | None = None,
    outcome: str | None = None,
    engagement_id: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Structured (not text-table) invocation list, for direct import by
    the security dashboard's Audit Log tab."""
    conn = _get_db()
    try:
        query = "SELECT id, ts, binary, args, mode, duration_ms, outcome, detail, engagement_id, raw_log_path FROM tool_invocations WHERE 1=1"
        params: list = []
        if binary:
            query += " AND binary=?"
            params.append(binary)
        if outcome:
            query += " AND outcome=?"
            params.append(outcome)
        if engagement_id:
            query += " AND engagement_id=?"
            params.append(engagement_id)
        query += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["args"] = json.loads(d["args"])
            except (json.JSONDecodeError, TypeError):
                pass  # truncated by _MAX_LOGGED_ARG_LEN -- leave as the raw (partial) string
            out.append(d)
        return out
    finally:
        conn.close()


def _stats(window_s: int = 86400) -> dict:
    """Counts by binary and by outcome over the trailing window, for direct
    import by the security dashboard's Audit Log tab summary row."""
    conn = _get_db()
    try:
        since = time.time() - window_s
        by_binary = conn.execute(
            "SELECT binary, COUNT(*) AS n FROM tool_invocations WHERE ts>? GROUP BY binary ORDER BY n DESC",
            (since,),
        ).fetchall()
        by_outcome = conn.execute(
            "SELECT outcome, COUNT(*) AS n FROM tool_invocations WHERE ts>? GROUP BY outcome",
            (since,),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) AS n FROM tool_invocations WHERE ts>?", (since,)).fetchone()["n"]
        return {
            "total": total,
            "by_binary": [dict(r) for r in by_binary],
            "by_outcome": [dict(r) for r in by_outcome],
        }
    finally:
        conn.close()


def _verify_chain() -> dict:
    """Walk tool_invocations in insertion (id) order, recomputing each
    row's expected hash from its own columns plus the *actual* preceding
    row's stored hash (mcp_servers/common.py's _compute_row_hash --
    same function _log_invocation() itself uses to write these), and
    comparing to what's actually stored. Detects both edits (a row's own
    hash won't match its content anymore) and deletions (the next
    surviving row's hash was computed assuming a predecessor that's no
    longer there, so it won't match the new "actual previous row" either)
    -- anyone with only filesystem access to audit.db, not the app's own
    secret_storage key, cannot recompute a replacement chain that
    verifies clean.

    Rows with no row_hash at all (written before this feature shipped)
    are skipped rather than reported as tampered -- when _log_invocation
    computed the *next* row's hash, it saw that predecessor's NULL hash
    and treated it as "no real predecessor" (_CHAIN_GENESIS), exactly
    like the start of a fresh chain; this mirrors that read-side so a
    legacy/pre-migration boundary doesn't look like a broken chain."""
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT id, ts, binary, args, mode, duration_ms, outcome, detail, "
            "engagement_id, raw_log_path, row_hash FROM tool_invocations ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return {"intact": True, "checked": 0, "total_rows": 0, "broken_at_id": None}

    prev_hash = _CHAIN_GENESIS
    checked = 0
    for row in rows:
        if not row["row_hash"]:
            prev_hash = _CHAIN_GENESIS
            continue
        expected = _compute_row_hash(
            prev_hash, row["ts"], row["binary"], row["args"], row["mode"],
            row["duration_ms"], row["outcome"], row["detail"],
            row["engagement_id"], row["raw_log_path"],
        )
        checked += 1
        if row["row_hash"] != expected:
            return {
                "intact": False, "checked": checked, "total_rows": len(rows),
                "broken_at_id": row["id"],
            }
        prev_hash = row["row_hash"]

    return {"intact": True, "checked": checked, "total_rows": len(rows), "broken_at_id": None}


TOOLS = [
    Tool(
        name="audit_list",
        description="List recent toolchain invocations (what ran, against what, when, how it turned out), optionally filtered by binary or outcome.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary": {"type": "string", "description": "e.g. 'nmap', 'sqlmap' -- omit for all"},
                "outcome": {"type": "string", "enum": list(_OUTCOMES)},
                "engagement_id": {"type": "string", "description": "Filter to invocations tagged with this engagement (\"Project\") -- omit for all"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    ),
    Tool(
        name="audit_stats",
        description="Summarize toolchain invocation counts by binary and by outcome over a trailing time window (default 24h).",
        inputSchema={
            "type": "object",
            "properties": {"window_hours": {"type": "number", "default": 24}},
        },
    ),
    Tool(
        name="audit_verify",
        description="Verify the audit trail's tamper-evidence hash chain end to end. Reports the chain intact through every row, or the exact row where it first breaks -- evidence someone edited or deleted a row without the app's own encryption key.",
        inputSchema={"type": "object", "properties": {}},
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "audit_list":
            rows = _list_invocations(
                binary=arguments.get("binary"),
                outcome=arguments.get("outcome"),
                engagement_id=arguments.get("engagement_id"),
                limit=arguments.get("limit", 50),
            )
            if not rows:
                result = "No invocations recorded yet."
            else:
                lines = [f"{'Time':<17} {'Binary':<14} {'Mode':<10} {'Outcome':<19} {'ms':<7} {'Engagement':<20} Args"]
                lines.append("-" * 120)
                for r in rows:
                    stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["ts"]))
                    args = r["args"] if isinstance(r["args"], str) else " ".join(str(a) for a in r["args"])
                    dur = str(r["duration_ms"]) if r["duration_ms"] is not None else "-"
                    eng = r["engagement_id"] or "-"
                    lines.append(f"{stamp:<17} {r['binary']:<14} {r['mode']:<10} {r['outcome']:<19} {dur:<7} {eng:<20} {args}")
                result = "\n".join(lines)

        elif name == "audit_stats":
            window_s = int(float(arguments.get("window_hours", 24)) * 3600)
            stats = _stats(window_s)
            if stats["total"] == 0:
                result = "No invocations recorded in this window."
            else:
                by_binary = ", ".join(f"{r['binary']}={r['n']}" for r in stats["by_binary"])
                by_outcome = ", ".join(f"{r['outcome']}={r['n']}" for r in stats["by_outcome"])
                result = f"Total: {stats['total']}\nBy binary: {by_binary}\nBy outcome: {by_outcome}"

        elif name == "audit_verify":
            v = _verify_chain()
            if v["total_rows"] == 0:
                result = "No invocations recorded yet -- nothing to verify."
            elif v["intact"]:
                result = f"Chain intact: {v['checked']} row(s) verified across {v['total_rows']} total row(s)."
            else:
                result = (
                    f"TAMPER DETECTED: chain broke at row id={v['broken_at_id']} "
                    f"(verified {v['checked']} row(s) before the break, {v['total_rows']} total row(s)). "
                    "That row's stored hash doesn't match what its own content + the true "
                    "preceding row's hash produce -- it (or a row before it) was edited or deleted "
                    "outside the app."
                )

        else:
            result = mcp_error("unknown_tool", name)

    except Exception as exc:  # noqa: BLE001
        result = mcp_error("db_error", str(exc))

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
