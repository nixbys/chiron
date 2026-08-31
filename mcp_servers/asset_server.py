"""
asset_server.py

MCP server for persistent asset inventory. Stores discovered hosts, services,
findings, and credentials in a local SQLite database inside the Odysseus data
directory. Provides deduplication and cross-session continuity.
"""

import asyncio
import json
import os
import sqlite3
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import mcp_error

server = Server("assets")

_DATA_DIR = Path(os.environ.get("ODYSSEUS_DATA_DIR", "./data"))
_DB_PATH = _DATA_DIR / "assets.db"


_db_initialized = False


def _get_db() -> sqlite3.Connection:
    global _db_initialized
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    if not _db_initialized:
        # Lazy schema init, on first real DB access rather than at import
        # time (module import happens before the MCP stdio handshake). An
        # eager call here previously crashed the whole process -- and with
        # it, tool *registration* -- if the data directory was missing or
        # unwritable at boot (bad volume permissions, full disk, a
        # read-only mount). Deferring it means the server still starts and
        # advertises its tools; a genuinely broken data directory now
        # surfaces as a normal per-call "db_error" MCP response (see the
        # try/except in call_tool below) instead of an opaque dead
        # subprocess the MCP client can only report as a transport failure.
        _init_db(conn)
        _db_initialized = True
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                hostname TEXT,
                os TEXT,
                criticality TEXT DEFAULT 'medium',
                tags TEXT DEFAULT '[]',
                first_seen REAL,
                last_seen REAL,
                notes TEXT DEFAULT '',
                UNIQUE(ip)
            );

            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
                port INTEGER,
                protocol TEXT,
                service_name TEXT,
                version TEXT,
                banner TEXT,
                first_seen REAL,
                last_seen REAL,
                UNIQUE(asset_id, port, protocol)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss REAL,
                cve_id TEXT,
                description TEXT,
                evidence TEXT,
                tool TEXT,
                status TEXT DEFAULT 'open',
                first_seen REAL,
                last_seen REAL
            );

            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
            CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
        """)
        # Migration: engagement_id groups assets/findings under an
        # mcp_servers/engagement_server.py engagement. Added after the
        # tables above shipped, so existing databases need an ALTER TABLE
        # rather than a fresh CREATE TABLE picking it up.
        asset_cols = {row[1] for row in conn.execute("PRAGMA table_info(assets)")}
        if "engagement_id" not in asset_cols:
            conn.execute("ALTER TABLE assets ADD COLUMN engagement_id TEXT")
        finding_cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
        if "engagement_id" not in finding_cols:
            conn.execute("ALTER TABLE findings ADD COLUMN engagement_id TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_engagement ON assets(engagement_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id)")


def _export_data(engagement_id: str | None = None, limit: int = 5000) -> dict:
    """Structured (not text-table) dump of this store's own three tables,
    for direct import by routes/export_routes.py -- same "small _get_*/
    _list_* helper for structured JSON" convention security_dashboard_
    routes.py's own docstring establishes, just returning everything at
    once since an export wants all three together. `services` is joined
    against `assets` for its `ip` (services itself has no engagement_id
    column -- it hangs off asset_id, not an engagement, directly)."""
    conn = _get_db()
    try:
        params: list = [limit]
        eng_clause = ""
        if engagement_id:
            eng_clause = " AND engagement_id=?"
            params = [engagement_id, limit]
        assets = [dict(r) for r in conn.execute(
            f"SELECT * FROM assets WHERE 1=1{eng_clause} ORDER BY last_seen DESC LIMIT ?", params,
        ).fetchall()]
        findings = [dict(r) for r in conn.execute(
            f"SELECT * FROM findings WHERE 1=1{eng_clause} ORDER BY last_seen DESC LIMIT ?", params,
        ).fetchall()]
        if engagement_id:
            services = [dict(r) for r in conn.execute(
                "SELECT s.*, a.ip AS asset_ip FROM services s JOIN assets a ON s.asset_id=a.id "
                "WHERE a.engagement_id=? ORDER BY s.last_seen DESC LIMIT ?",
                [engagement_id, limit],
            ).fetchall()]
        else:
            services = [dict(r) for r in conn.execute(
                "SELECT s.*, a.ip AS asset_ip FROM services s JOIN assets a ON s.asset_id=a.id "
                "ORDER BY s.last_seen DESC LIMIT ?",
                [limit],
            ).fetchall()]
        for row in assets + findings:
            if "tags" in row:
                try:
                    row["tags"] = json.loads(row["tags"] or "[]")
                except (json.JSONDecodeError, TypeError):
                    pass
        return {"assets": assets, "services": services, "findings": findings}
    finally:
        conn.close()


TOOLS = [
    Tool(
        name="asset_add",
        description="Add or update a host in the asset inventory.",
        inputSchema={
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
                "hostname": {"type": "string", "default": ""},
                "os": {"type": "string", "default": ""},
                "criticality": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "default": "medium",
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Labels (e.g. ['web', 'dmz', 'internal'])",
                    "default": [],
                },
                "notes": {"type": "string", "default": ""},
                "engagement_id": {"type": "string", "description": "Group this asset under an engagement (see engagement_server's engagement_create)"},
            },
            "required": ["ip"],
        },
    ),
    Tool(
        name="service_add",
        description="Record an open service discovered on a host.",
        inputSchema={
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
                "port": {"type": "integer"},
                "protocol": {"type": "string", "enum": ["tcp", "udp"], "default": "tcp"},
                "service_name": {"type": "string", "default": "unknown"},
                "version": {"type": "string", "default": ""},
                "banner": {"type": "string", "default": ""},
            },
            "required": ["ip", "port"],
        },
    ),
    Tool(
        name="finding_add",
        description="Record a security finding linked to an asset.",
        inputSchema={
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "ip": {"type": "string", "description": "IP of affected asset (optional)"},
                "cvss": {"type": "number", "description": "CVSS base score (0-10)"},
                "cve_id": {"type": "string", "description": "CVE identifier (optional)"},
                "description": {"type": "string"},
                "evidence": {"type": "string", "description": "Raw tool output or proof"},
                "tool": {"type": "string", "description": "Tool that found this (e.g. nuclei, nmap)"},
                "engagement_id": {"type": "string", "description": "Group this finding under an engagement (see engagement_server's engagement_create)"},
            },
            "required": ["title", "severity"],
        },
    ),
    Tool(
        name="asset_list",
        description="List all assets in the inventory, optionally filtered by criticality, tag, or engagement.",
        inputSchema={
            "type": "object",
            "properties": {
                "criticality": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                "tag": {"type": "string"},
                "engagement_id": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    ),
    Tool(
        name="finding_list",
        description="List findings, optionally filtered by severity, status, asset IP, or engagement.",
        inputSchema={
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "status": {"type": "string", "enum": ["open", "remediated", "accepted", "false_positive"]},
                "ip": {"type": "string"},
                "engagement_id": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    ),
    Tool(
        name="finding_update",
        description="Update the status of a finding (e.g. mark as remediated or false positive).",
        inputSchema={
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer"},
                "status": {
                    "type": "string",
                    "enum": ["open", "remediated", "accepted", "false_positive"],
                },
                "notes": {"type": "string"},
            },
            "required": ["finding_id", "status"],
        },
    ),
    Tool(
        name="asset_summary",
        description="Return a summary of the asset inventory: counts, severity breakdown, top risks.",
        inputSchema={"type": "object", "properties": {}},
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

        if name == "asset_add":
            ip = arguments["ip"]
            tags = json.dumps(arguments.get("tags", []))
            conn.execute("""
                INSERT INTO assets (ip, hostname, os, criticality, tags, first_seen, last_seen, notes, engagement_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    hostname=excluded.hostname, os=excluded.os,
                    criticality=excluded.criticality, tags=excluded.tags,
                    last_seen=excluded.last_seen, notes=excluded.notes,
                    engagement_id=COALESCE(excluded.engagement_id, assets.engagement_id)
            """, (ip, arguments.get("hostname", ""), arguments.get("os", ""),
                  arguments.get("criticality", "medium"), tags, now, now,
                  arguments.get("notes", ""), arguments.get("engagement_id")))
            conn.commit()
            result = f"Asset {ip} recorded."

        elif name == "service_add":
            ip = arguments["ip"]
            row = conn.execute("SELECT id FROM assets WHERE ip=?", (ip,)).fetchone()
            if not row:
                conn.execute("INSERT INTO assets (ip, first_seen, last_seen) VALUES (?, ?, ?)", (ip, now, now))
                conn.commit()
                row = conn.execute("SELECT id FROM assets WHERE ip=?", (ip,)).fetchone()
            asset_id = row["id"]
            conn.execute("""
                INSERT INTO services (asset_id, port, protocol, service_name, version, banner, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id, port, protocol) DO UPDATE SET
                    service_name=excluded.service_name, version=excluded.version,
                    banner=excluded.banner, last_seen=excluded.last_seen
            """, (asset_id, arguments["port"], arguments.get("protocol", "tcp"),
                  arguments.get("service_name", "unknown"), arguments.get("version", ""),
                  arguments.get("banner", ""), now, now))
            conn.commit()
            result = f"Service {arguments['port']}/{arguments.get('protocol','tcp')} recorded on {ip}."

        elif name == "finding_add":
            ip = arguments.get("ip")
            asset_id = None
            if ip:
                row = conn.execute("SELECT id FROM assets WHERE ip=?", (ip,)).fetchone()
                asset_id = row["id"] if row else None
            conn.execute("""
                INSERT INTO findings
                    (asset_id, title, severity, cvss, cve_id, description, evidence, tool, first_seen, last_seen, engagement_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (asset_id, arguments["title"], arguments["severity"],
                  arguments.get("cvss"), arguments.get("cve_id"),
                  arguments.get("description", ""), arguments.get("evidence", ""),
                  arguments.get("tool", ""), now, now, arguments.get("engagement_id")))
            conn.commit()
            result = f"Finding '{arguments['title']}' ({arguments['severity']}) recorded."

        elif name == "asset_list":
            query = "SELECT ip, hostname, os, criticality, tags, last_seen FROM assets WHERE 1=1"
            params: list = []
            if crit := arguments.get("criticality"):
                query += " AND criticality=?"
                params.append(crit)
            if engagement_id := arguments.get("engagement_id"):
                query += " AND engagement_id=?"
                params.append(engagement_id)
            query += " ORDER BY last_seen DESC LIMIT ?"
            params.append(arguments.get("limit", 50))
            rows = conn.execute(query, params).fetchall()
            if not rows:
                result = "No assets found."
            else:
                lines = [f"{'IP':<18} {'Hostname':<30} {'OS':<20} {'Criticality':<10} {'Tags'}"]
                lines.append("-" * 90)
                for r in rows:
                    tags = json.loads(r["tags"] or "[]")
                    lines.append(f"{r['ip']:<18} {r['hostname'] or '':<30} {r['os'] or '':<20} {r['criticality']:<10} {','.join(tags)}")
                result = "\n".join(lines)

        elif name == "finding_list":
            query = "SELECT f.id, f.title, f.severity, f.cve_id, f.status, a.ip, f.tool FROM findings f LEFT JOIN assets a ON f.asset_id=a.id WHERE 1=1"
            params = []
            if sev := arguments.get("severity"):
                query += " AND f.severity=?"
                params.append(sev)
            if status := arguments.get("status"):
                query += " AND f.status=?"
                params.append(status)
            if ip := arguments.get("ip"):
                query += " AND a.ip=?"
                params.append(ip)
            if engagement_id := arguments.get("engagement_id"):
                query += " AND f.engagement_id=?"
                params.append(engagement_id)
            query += " ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, f.last_seen DESC LIMIT ?"
            params.append(arguments.get("limit", 50))
            rows = conn.execute(query, params).fetchall()
            if not rows:
                result = "No findings."
            else:
                lines = [f"{'ID':<6} {'Severity':<10} {'Status':<15} {'CVE':<18} {'IP':<16} {'Tool':<12} Title"]
                lines.append("-" * 100)
                for r in rows:
                    lines.append(f"{r['id']:<6} {r['severity']:<10} {r['status']:<15} {r['cve_id'] or '':<18} {r['ip'] or '':<16} {r['tool'] or '':<12} {r['title']}")
                result = "\n".join(lines)

        elif name == "finding_update":
            conn.execute("UPDATE findings SET status=? WHERE id=?",
                         (arguments["status"], arguments["finding_id"]))
            conn.commit()
            result = f"Finding {arguments['finding_id']} updated to '{arguments['status']}'."

        elif name == "asset_summary":
            total_assets = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            total_findings = conn.execute("SELECT COUNT(*) FROM findings WHERE status='open'").fetchone()[0]
            by_sev = conn.execute(
                "SELECT severity, COUNT(*) as n FROM findings WHERE status='open' GROUP BY severity"
            ).fetchall()
            top_risks = conn.execute(
                "SELECT a.ip, COUNT(f.id) as n FROM findings f JOIN assets a ON f.asset_id=a.id "
                "WHERE f.status='open' AND f.severity IN ('critical','high') "
                "GROUP BY a.ip ORDER BY n DESC LIMIT 5"
            ).fetchall()
            sev_lines = "  ".join(f"{r['severity']}:{r['n']}" for r in by_sev)
            risk_lines = "\n".join(f"  {r['ip']} — {r['n']} critical/high finding(s)" for r in top_risks)
            result = (
                f"Assets: {total_assets}  Open findings: {total_findings}\n"
                f"By severity: {sev_lines}\n"
                f"Top risks:\n{risk_lines or '  (none)'}"
            )

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
