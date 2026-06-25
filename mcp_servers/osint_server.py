"""
osint_server.py

MCP server for passive OSINT collection: theHarvester, Sherlock (username search),
DNS enumeration, WHOIS, and Amass subdomain discovery.
All tools run inside the odysseus-toolchain sidecar.
"""

import asyncio
import sys
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import exec_in_toolchain, mcp_error, validate_domain

server = Server("osint")

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
                    "description": "Comma-separated data sources",
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
        description="Enumerate DNS records (A, MX, NS, TXT, CNAME, SOA) for a domain.",
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "record_types": {
                    "type": "string",
                    "description": "Space-separated record types",
                    "default": "A MX NS TXT CNAME SOA",
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
    Tool(
        name="subdomain_enum",
        description=(
            "Enumerate subdomains using Amass passive mode. "
            "Fast passive discovery using certificate transparency, DNS brute-force, and APIs."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Root domain to enumerate"},
                "passive": {
                    "type": "boolean",
                    "description": "Passive mode only (no active DNS probing)",
                    "default": True,
                },
                "timeout": {"type": "integer", "default": 120},
            },
            "required": ["domain"],
        },
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "harvester":
        domain = arguments["domain"]
        if err := validate_domain(domain):
            return [TextContent(type="text", text=err)]
        sources = arguments.get("sources", "bing,google,dnsdumpster,crtsh")
        limit = str(arguments.get("limit", 200))
        result = exec_in_toolchain(
            ["theHarvester", "-d", domain, "-b", sources, "-l", limit],
            timeout=180,
        )

    elif name == "username_search":
        username = arguments["username"]
        timeout = int(arguments.get("timeout", 60))
        result = exec_in_toolchain(["sherlock", username, "--print-found"], timeout=timeout)

    elif name == "dns_enum":
        domain = arguments["domain"]
        if err := validate_domain(domain):
            return [TextContent(type="text", text=err)]
        record_types = arguments.get("record_types", "A MX NS TXT CNAME SOA").split()
        lines = []
        for rtype in record_types:
            out = exec_in_toolchain(["dig", "+short", rtype, domain], timeout=10)
            lines.append(f"[{rtype}]\n{out}")
        result = "\n\n".join(lines)

    elif name == "whois_lookup":
        result = exec_in_toolchain(["whois", arguments["target"]], timeout=30)

    elif name == "subdomain_enum":
        domain = arguments["domain"]
        if err := validate_domain(domain):
            return [TextContent(type="text", text=err)]
        passive = arguments.get("passive", True)
        timeout = int(arguments.get("timeout", 120))
        cmd = ["amass", "enum", "-d", domain, "-silent"]
        if passive:
            cmd.append("-passive")
        result = exec_in_toolchain(cmd, timeout=timeout)

    else:
        result = mcp_error("unknown_tool", name)

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
