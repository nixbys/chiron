"""
intel_server.py

MCP server for threat intelligence lookups: Shodan, VirusTotal, CVE/NVD, and AlienVault OTX.
All lookups are passive/read-only — no active scanning occurs here.
API keys are read from environment variables; missing keys disable the relevant tool gracefully.
"""

import asyncio
import os
import sys
from pathlib import Path

import requests

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

server = Server("intel")

_SHODAN_KEY = os.environ.get("SHODAN_API_KEY", "")
_VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
_OTX_KEY = os.environ.get("OTX_API_KEY", "")
_NVD_KEY = os.environ.get("NVD_API_KEY", "")  # optional — NVD rate-limits without key

_REQUEST_TIMEOUT = 15  # seconds

TOOLS = [
    Tool(
        name="shodan_host",
        description="Look up a host IP on Shodan. Returns open ports, banners, CVEs, and org info.",
        inputSchema={
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "IPv4 address to look up"}},
            "required": ["ip"],
        },
    ),
    Tool(
        name="virustotal_lookup",
        description="Check a file hash, URL, domain, or IP against VirusTotal.",
        inputSchema={
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "Hash (MD5/SHA1/SHA256), URL, domain, or IP"},
                "kind": {
                    "type": "string",
                    "enum": ["file", "url", "domain", "ip"],
                    "description": "Indicator type",
                },
            },
            "required": ["indicator", "kind"],
        },
    ),
    Tool(
        name="cve_lookup",
        description="Search the NVD for CVEs by ID (e.g. CVE-2024-1234) or keyword.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "CVE ID or keyword (e.g. 'apache log4j')"},
                "limit": {"type": "integer", "default": 10},
            },
            "required": ["query"],
        },
    ),
    Tool(
        name="otx_indicator",
        description="Query AlienVault OTX for threat intelligence on a domain, IP, hash, or URL.",
        inputSchema={
            "type": "object",
            "properties": {
                "indicator": {"type": "string"},
                "kind": {
                    "type": "string",
                    "enum": ["domain", "IPv4", "file", "url"],
                },
            },
            "required": ["indicator", "kind"],
        },
    ),
]


def _require_key(name: str, value: str) -> str | None:
    if not value:
        return f"[error] {name} API key not set. Add it to your .env file."
    return None


def _get(url: str, headers: dict | None = None, params: dict | None = None) -> dict:
    try:
        resp = requests.get(url, headers=headers or {}, params=params or {}, timeout=_REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.HTTPError as exc:
        return {"error": f"HTTP {exc.response.status_code}: {exc.response.text[:300]}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _shodan_host(ip: str) -> str:
    if err := _require_key("SHODAN_API_KEY", _SHODAN_KEY):
        return err
    data = _get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": _SHODAN_KEY})
    if "error" in data:
        return f"[shodan error] {data['error']}"
    ports = data.get("ports", [])
    org = data.get("org", "unknown")
    country = data.get("country_name", "unknown")
    vulns = list(data.get("vulns", {}).keys())
    lines = [
        f"IP: {ip}  Org: {org}  Country: {country}",
        f"Open ports: {ports}",
        f"CVEs (Shodan): {vulns or 'none reported'}",
    ]
    hostnames = data.get("hostnames", [])
    if hostnames:
        lines.append(f"Hostnames: {hostnames}")
    return "\n".join(lines)


def _vt_lookup(indicator: str, kind: str) -> str:
    if err := _require_key("VIRUSTOTAL_API_KEY", _VT_KEY):
        return err
    endpoints = {
        "file": f"https://www.virustotal.com/api/v3/files/{indicator}",
        "url": "https://www.virustotal.com/api/v3/urls",
        "domain": f"https://www.virustotal.com/api/v3/domains/{indicator}",
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
    }
    url = endpoints.get(kind, "")
    if not url:
        return f"[error] Unknown indicator kind: {kind}"
    headers = {"x-apikey": _VT_KEY}
    data = _get(url, headers=headers)
    if "error" in data and isinstance(data["error"], dict):
        return f"[VT error] {data['error'].get('message', data['error'])}"
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return (
        f"Malicious: {stats.get('malicious', '?')}  "
        f"Suspicious: {stats.get('suspicious', '?')}  "
        f"Harmless: {stats.get('harmless', '?')}  "
        f"Undetected: {stats.get('undetected', '?')}"
    )


def _nvd_lookup(query: str, limit: int = 10) -> str:
    params: dict = {"resultsPerPage": limit}
    if query.upper().startswith("CVE-"):
        params["cveId"] = query.upper()
    else:
        params["keywordSearch"] = query
    headers = {}
    if _NVD_KEY:
        headers["apiKey"] = _NVD_KEY
    data = _get("https://services.nvd.nist.gov/rest/json/cves/2.0", headers=headers, params=params)
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return "No CVEs found."
    lines = []
    for v in vulns[:limit]:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "?")
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "No description",
        )
        metrics = cve.get("metrics", {})
        score = "?"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore", "?")
                break
        lines.append(f"{cve_id}  CVSS:{score}  {desc[:120]}")
    return "\n".join(lines)


def _otx_lookup(indicator: str, kind: str) -> str:
    if err := _require_key("OTX_API_KEY", _OTX_KEY):
        return err
    url = f"https://otx.alienvault.com/api/v1/indicators/{kind}/{indicator}/general"
    headers = {"X-OTX-API-KEY": _OTX_KEY}
    data = _get(url, headers=headers)
    if "error" in data:
        return f"[OTX error] {data['error']}"
    pulse_count = data.get("pulse_info", {}).get("count", 0)
    reputation = data.get("reputation", 0)
    return f"OTX pulses: {pulse_count}  Reputation score: {reputation}"


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "shodan_host":
        result = _shodan_host(arguments["ip"])
    elif name == "virustotal_lookup":
        result = _vt_lookup(arguments["indicator"], arguments["kind"])
    elif name == "cve_lookup":
        result = _nvd_lookup(arguments["query"], int(arguments.get("limit", 10)))
    elif name == "otx_indicator":
        result = _otx_lookup(arguments["indicator"], arguments["kind"])
    else:
        result = f"[error] Unknown tool: {name}"
    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
