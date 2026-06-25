"""
risk_server.py

MCP server for risk scoring and prioritized remediation planning.
Aggregates findings from the asset inventory database, computes risk scores
using CVSS + asset criticality weighting, and produces prioritized remediation queues.

Risk score = CVSS_base * criticality_multiplier * exploitability_factor
"""

import asyncio
import json
import os
import sqlite3
import sys
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import mcp_error

server = Server("risk")

_DATA_DIR = Path(os.environ.get("ODYSSEUS_DATA_DIR", "./data"))
_DB_PATH = _DATA_DIR / "assets.db"

# Criticality multipliers
_CRIT_MULT = {"critical": 2.0, "high": 1.5, "medium": 1.0, "low": 0.5}

# Severity base CVSS estimates when no CVSS score is recorded
_SEV_BASE = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}

# Known-exploited multiplier (approximate — integrate KEV for accuracy)
_KNOWN_EXPLOITED_BONUS = 1.3


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _risk_score(cvss: float | None, severity: str, asset_criticality: str, cve_id: str | None) -> float:
    base = cvss if cvss and cvss > 0 else _SEV_BASE.get(severity, 5.0)
    mult = _CRIT_MULT.get(asset_criticality, 1.0)
    score = base * mult
    # Very rough KEV proxy: CVEs with high CVSS from common families
    if cve_id and float(base) >= 9.0:
        score *= _KNOWN_EXPLOITED_BONUS
    return round(min(score, 30.0), 2)  # cap at 30 for display


TOOLS = [
    Tool(
        name="risk_summary",
        description=(
            "Compute risk scores for all open findings and return a prioritized summary. "
            "Combines CVSS scores with asset criticality to produce ranked remediation queue."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 20, "description": "Top N findings to return"},
                "min_severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "default": "medium",
                },
            },
        },
    ),
    Tool(
        name="asset_risk",
        description="Compute the aggregate risk score for a specific host IP.",
        inputSchema={
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
        },
    ),
    Tool(
        name="remediation_plan",
        description=(
            "Generate a prioritized remediation plan grouped by risk tier. "
            "Returns actionable remediation steps for critical and high-risk findings."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "limit_per_tier": {"type": "integer", "default": 5},
            },
        },
    ),
    Tool(
        name="risk_score_finding",
        description="Compute the risk score for a single finding by ID.",
        inputSchema={
            "type": "object",
            "properties": {"finding_id": {"type": "integer"}},
            "required": ["finding_id"],
        },
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if not _DB_PATH.exists():
        return [TextContent(type="text", text=mcp_error("no_db", "Asset database not found. Add assets first using asset_server."))]

    try:
        conn = _db()

        if name == "risk_summary":
            limit = int(arguments.get("limit", 20))
            min_sev = arguments.get("min_severity", "medium")
            sev_order = ["critical", "high", "medium", "low", "info"]
            min_idx = sev_order.index(min_sev) if min_sev in sev_order else 2

            rows = conn.execute("""
                SELECT f.id, f.title, f.severity, f.cvss, f.cve_id, f.tool,
                       a.ip, a.criticality
                FROM findings f
                LEFT JOIN assets a ON f.asset_id = a.id
                WHERE f.status = 'open'
            """).fetchall()

            scored = []
            for r in rows:
                sev_idx = sev_order.index(r["severity"]) if r["severity"] in sev_order else 4
                if sev_idx > min_idx:
                    continue
                score = _risk_score(r["cvss"], r["severity"], r["criticality"] or "medium", r["cve_id"])
                scored.append((score, r))

            scored.sort(reverse=True)
            lines = [f"Top {limit} open findings by risk score (min severity: {min_sev}):"]
            lines.append(f"\n{'Score':<8} {'Sev':<10} {'CVE':<18} {'IP':<16} {'Tool':<12} Title")
            lines.append("-" * 100)
            for score, r in scored[:limit]:
                lines.append(
                    f"{score:<8} {r['severity']:<10} {r['cve_id'] or '':<18} "
                    f"{r['ip'] or '':<16} {r['tool'] or '':<12} {r['title']}"
                )
            result = "\n".join(lines)

        elif name == "asset_risk":
            ip = arguments["ip"]
            asset = conn.execute("SELECT * FROM assets WHERE ip=?", (ip,)).fetchone()
            if not asset:
                return [TextContent(type="text", text=mcp_error("not_found", f"Asset {ip} not in inventory"))]
            findings = conn.execute(
                "SELECT f.* FROM findings f JOIN assets a ON f.asset_id=a.id WHERE a.ip=? AND f.status='open'",
                (ip,),
            ).fetchall()
            if not findings:
                return [TextContent(type="text", text=f"Asset {ip}: no open findings.")]
            total = sum(_risk_score(f["cvss"], f["severity"], asset["criticality"] or "medium", f["cve_id"]) for f in findings)
            top = sorted(findings, key=lambda f: _risk_score(f["cvss"], f["severity"], asset["criticality"] or "medium", f["cve_id"]), reverse=True)
            lines = [
                f"Asset: {ip}  Criticality: {asset['criticality']}  Open findings: {len(findings)}",
                f"Aggregate risk score: {round(total, 2)}\n",
                "Top findings:",
            ]
            for f in top[:5]:
                score = _risk_score(f["cvss"], f["severity"], asset["criticality"] or "medium", f["cve_id"])
                lines.append(f"  [{score:>6}] ({f['severity']}) {f['title']}")
            result = "\n".join(lines)

        elif name == "remediation_plan":
            limit = int(arguments.get("limit_per_tier", 5))
            rows = conn.execute("""
                SELECT f.id, f.title, f.severity, f.cvss, f.cve_id, f.description, f.tool,
                       a.ip, a.criticality
                FROM findings f
                LEFT JOIN assets a ON f.asset_id=a.id
                WHERE f.status='open'
            """).fetchall()

            tiers: dict[str, list] = {"immediate": [], "short_term": [], "planned": []}
            for r in rows:
                score = _risk_score(r["cvss"], r["severity"], r["criticality"] or "medium", r["cve_id"])
                if score >= 14:
                    tiers["immediate"].append((score, r))
                elif score >= 7:
                    tiers["short_term"].append((score, r))
                else:
                    tiers["planned"].append((score, r))

            lines = ["# Prioritized Remediation Plan\n"]
            labels = {"immediate": "IMMEDIATE (score ≥14)", "short_term": "SHORT-TERM (7–13)", "planned": "PLANNED (<7)"}
            for tier_key, label in labels.items():
                items = sorted(tiers[tier_key], reverse=True)[:limit]
                lines.append(f"## {label} — {len(tiers[tier_key])} finding(s)\n")
                for score, r in items:
                    lines.append(f"  [{score:>6}] ID:{r['id']} ({r['severity']}) {r['title']}")
                    if r["ip"]:
                        lines.append(f"           Asset: {r['ip']}")
                    if r["cve_id"]:
                        lines.append(f"           CVE: {r['cve_id']}")
                    if r["description"]:
                        lines.append(f"           {r['description'][:120]}...")
                lines.append("")
            result = "\n".join(lines)

        elif name == "risk_score_finding":
            fid = arguments["finding_id"]
            row = conn.execute("""
                SELECT f.*, a.criticality FROM findings f
                LEFT JOIN assets a ON f.asset_id=a.id WHERE f.id=?
            """, (fid,)).fetchone()
            if not row:
                return [TextContent(type="text", text=mcp_error("not_found", f"Finding {fid} not found"))]
            score = _risk_score(row["cvss"], row["severity"], row["criticality"] or "medium", row["cve_id"])
            result = (
                f"Finding {fid}: {row['title']}\n"
                f"Severity: {row['severity']}  CVSS: {row['cvss'] or 'N/A'}  CVE: {row['cve_id'] or 'N/A'}\n"
                f"Asset criticality: {row['criticality'] or 'medium'}\n"
                f"Risk score: {score}"
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
