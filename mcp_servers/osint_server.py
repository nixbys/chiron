"""
osint_server.py

MCP server for passive OSINT collection: theHarvester, Sherlock (username search),
DNS enumeration, and WHOIS. All tools run inside the odysseus-toolchain sidecar.
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

server = Server("osint")

_TOOLCHAIN_API = os.environ.get("ODYSSEUS_TOOLCHAIN_API", "http://odysseus-toolchain:8088")

TOOLS = [
    Tool(
        name="harvester",
        description=(
            "Run theHarvester to collect emails, subdomains, hosts, and employee names "
            "from public sources for a given domain."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain (e.g. example.com)"},
                "sources": {
                    "type": "string",
                    "description": "Comma-separated data sources (default: bing,google,dnsdumpster,crtsh)",
                    "default": "bing,google,dnsdumpster,crtsh",
                },
                "limit": {"type": "integer", "default": 200},
            },
            "required": ["domain"],
        },
    ),
    Tool(
        name="username_search",
        description="Search for a username across social platforms using Sherlock.",
        inputSchema={
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "timeout": {"type": "integer", "default": 60},
            },
            "required": ["username"],
        },
    ),
    Tool(
        name="dns_enum",
        description="Enumerate DNS records (A, MX, NS, TXT, CNAME) for a domain.",
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "record_types": {
                    "type": "string",
                    "description": "Space-separated record types",
                    "default": "A MX NS TXT CNAME",
                },
            },
            "required": ["domain"],
        },
    ),
    Tool(
        name="whois_lookup",
        description="Perform a WHOIS lookup on a domain or IP address.",
        inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    ),
]


def _exec(cmd: list[str], timeout: int = 120) -> str:
    try:
        resp = requests.post(
            f"{_TOOLCHAIN_API}/exec",
            json={"args": cmd, "timeout": timeout},
            timeout=timeout + 5,
        )
        resp.raise_for_status()
        data = resp.json()
        out = (data.get("stdout") or "") + (
            f"\n[stderr]\n{data['stderr']}" if data.get("stderr") else ""
        )
        return out.strip() or "(no output)"
    except requests.exceptions.Timeout:
        return f"[timeout] Command exceeded {timeout}s."
    except Exception as exc:  # noqa: BLE001
        return f"[error] {exc}"


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "harvester":
        domain = arguments["domain"]
        sources = arguments.get("sources", "bing,google,dnsdumpster,crtsh")
        limit = str(arguments.get("limit", 200))
        result = _exec(
            ["theHarvester", "-d", domain, "-b", sources, "-l", limit],
            timeout=180,
        )

    elif name == "username_search":
        username = arguments["username"]
        timeout = int(arguments.get("timeout", 60))
        result = _exec(["sherlock", username, "--print-found"], timeout=timeout)

    elif name == "dns_enum":
        domain = arguments["domain"]
        record_types = arguments.get("record_types", "A MX NS TXT CNAME").split()
        lines = []
        for rtype in record_types:
            out = _exec(["dig", "+short", rtype, domain], timeout=10)
            lines.append(f"[{rtype}]\n{out}")
        result = "\n\n".join(lines)

    elif name == "whois_lookup":
        result = _exec(["whois", arguments["target"]], timeout=30)

    else:
        result = f"[error] Unknown tool: {name}"

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
