"""
intel_server.py

MCP server for threat intelligence lookups: Shodan, VirusTotal, CVE/NVD, OTX, and Censys.
All lookups are passive/read-only. API keys are read from environment variables;
missing keys disable the relevant tool gracefully.
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
from mcp_servers.common import mcp_error

server = Server("intel")

_SHODAN_KEY = os.environ.get("SHODAN_API_KEY", "")
_VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
_OTX_KEY = os.environ.get("OTX_API_KEY", "")
_NVD_KEY = os.environ.get("NVD_API_KEY", "")
_CENSYS_ID = os.environ.get("CENSYS_API_ID", "")
_CENSYS_SECRET = os.environ.get("CENSYS_API_SECRET", "")

_REQUEST_TIMEOUT = 15

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
                "indicator": {
                    "type": "string",
                    "description": "Hash (MD5/SHA1/SHA256), URL, domain, or IP",
                },
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
                "query": {
                    "type": "string",
                    "description": "CVE ID or keyword (e.g. 'apache log4j')",
                },
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
    Tool(
        name="censys_host",
        description=(
            "Look up a host IP on Censys. Returns open services, TLS certificates, "
            "and autonomous system info."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4 address to look up"},
            },
            "required": ["ip"],
        },
    ),
    Tool(
        name="censys_search",
        description=(
            "Search Censys for hosts matching a query. "
            "Uses Censys Search Language (e.g. 'services.port=8080 and services.transport_protocol=TCP')."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Censys search query"},
                "limit": {"type": "integer", "default": 10},
            },
            "required": ["query"],
        },
    ),
]


def _require_key(name: str, value: str) -> str | None:
    if not value:
        return mcp_error("no_api_key", f"{name} not set — add it to your .env file")
    return None


def _get(url: str, headers: dict | None = None, params: dict | None = None,
         auth: tuple | None = None) -> dict:
    try:
        resp = requests.get(
            url,
            headers=headers or {},
            params=params or {},
            auth=auth,
            timeout=_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.HTTPError as exc:
        return {"_mcp_error": f"HTTP {exc.response.status_code}: {exc.response.text[:300]}"}
    except Exception as exc:  # noqa: BLE001
        return {"_mcp_error": str(exc)}


def _shodan_host(ip: str) -> str:
    if err := _require_key("SHODAN_API_KEY", _SHODAN_KEY):
        return err
    data = _get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": _SHODAN_KEY})
    if "_mcp_error" in data:
        return mcp_error("shodan", data["_mcp_error"])
    ports = data.get("ports", [])
    org = data.get("org", "unknown")
    country = data.get("country_name", "unknown")
    vulns = list(data.get("vulns", {}).keys())
    lines = [
        f"IP: {ip}  Org: {org}  Country: {country}",
        f"Open ports: {ports}",
        f"CVEs (Shodan): {vulns or 'none reported'}",
    ]
    if hostnames := data.get("hostnames", []):
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
    if kind not in endpoints:
        return mcp_error("invalid_kind", f"Unknown indicator kind: {kind}")
    data = _get(endpoints[kind], headers={"x-apikey": _VT_KEY})
    if "_mcp_error" in data:
        return mcp_error("virustotal", data["_mcp_error"])
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
    headers = {"apiKey": _NVD_KEY} if _NVD_KEY else {}
    data = _get("https://services.nvd.nist.gov/rest/json/cves/2.0", headers=headers, params=params)
    if "_mcp_error" in data:
        return mcp_error("nvd", data["_mcp_error"])
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
            if entries := metrics.get(key, []):
                score = entries[0].get("cvssData", {}).get("baseScore", "?")
                break
        lines.append(f"{cve_id}  CVSS:{score}  {desc[:120]}")
    return "\n".join(lines)


def _otx_lookup(indicator: str, kind: str) -> str:
    if err := _require_key("OTX_API_KEY", _OTX_KEY):
        return err
    data = _get(
        f"https://otx.alienvault.com/api/v1/indicators/{kind}/{indicator}/general",
        headers={"X-OTX-API-KEY": _OTX_KEY},
    )
    if "_mcp_error" in data:
        return mcp_error("otx", data["_mcp_error"])
    pulse_count = data.get("pulse_info", {}).get("count", 0)
    reputation = data.get("reputation", 0)
    return f"OTX pulses: {pulse_count}  Reputation score: {reputation}"


def _censys_host(ip: str) -> str:
    if not _CENSYS_ID or not _CENSYS_SECRET:
        return mcp_error("no_api_key", "CENSYS_API_ID and CENSYS_API_SECRET not set — add them to .env")
    data = _get(
        f"https://search.censys.io/api/v2/hosts/{ip}",
        auth=(_CENSYS_ID, _CENSYS_SECRET),
    )
    if "_mcp_error" in data:
        return mcp_error("censys", data["_mcp_error"])
    result = data.get("result", {})
    services = result.get("services", [])
    asn = result.get("autonomous_system", {})
    lines = [
        f"IP: {ip}  AS: {asn.get('asn', '?')} ({asn.get('name', '?')})  Country: {result.get('location', {}).get('country', '?')}",
        f"Services ({len(services)}):",
    ]
    for svc in services[:10]:
        port = svc.get("port", "?")
        proto = svc.get("transport_protocol", "?")
        name = svc.get("service_name", "unknown")
        lines.append(f"  {port}/{proto}  {name}")
    return "\n".join(lines)


def _censys_search(query: str, limit: int = 10) -> str:
    if not _CENSYS_ID or not _CENSYS_SECRET:
        return mcp_error("no_api_key", "CENSYS_API_ID and CENSYS_API_SECRET not set — add them to .env")
    try:
        resp = requests.post(
            "https://search.censys.io/api/v2/hosts/search",
            auth=(_CENSYS_ID, _CENSYS_SECRET),
            json={"q": query, "per_page": min(limit, 100)},
            timeout=_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return mcp_error("censys", str(exc))
    hits = data.get("result", {}).get("hits", [])
    if not hits:
        return "No results."
    lines = [f"Results for: {query}"]
    for h in hits:
        ip = h.get("ip", "?")
        services = [f"{s.get('port')}/{s.get('transport_protocol')}" for s in h.get("services", [])]
        lines.append(f"  {ip}  {', '.join(services[:5])}")
    return "\n".join(lines)


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
    elif name == "censys_host":
        result = _censys_host(arguments["ip"])
    elif name == "censys_search":
        result = _censys_search(arguments["query"], int(arguments.get("limit", 10)))
    else:
        result = mcp_error("unknown_tool", name)
    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
