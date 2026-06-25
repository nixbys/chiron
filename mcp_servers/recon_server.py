"""
recon_server.py

MCP server for network reconnaissance tools (nmap, masscan).
All scans are executed inside the odysseus-toolchain sidecar container.
The caller is responsible for obtaining written authorization before targeting any host.
"""

import asyncio
import sys
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import exec_in_toolchain, mcp_error, validate_ip

server = Server("recon")

TOOLS = [
    Tool(
        name="nmap_scan",
        description=(
            "Run an nmap scan against an authorized target. "
            "Returns raw nmap output. Requires explicit authorization."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP address, hostname, or CIDR range (authorized targets only)",
                },
                "flags": {
                    "type": "string",
                    "description": "nmap flags (default: -sV -T4 --open)",
                    "default": "-sV -T4 --open",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max seconds to wait for scan completion",
                    "default": 300,
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="masscan_scan",
        description=(
            "High-speed TCP port scan with masscan against an authorized target. "
            "Requires NET_RAW capability (runs inside toolchain container)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or CIDR (authorized only)"},
                "ports": {
                    "type": "string",
                    "description": "Port range, e.g. '1-65535' or '80,443,8080'",
                    "default": "1-1000",
                },
                "rate": {"type": "integer", "description": "Packets per second", "default": 1000},
            },
            "required": ["target"],
        },
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "nmap_scan":
        target = arguments["target"]
        if err := validate_ip(target):
            return [TextContent(type="text", text=err)]
        flags = arguments.get("flags", "-sV -T4 --open").split()
        timeout = int(arguments.get("timeout", 300))
        result = exec_in_toolchain(["nmap"] + flags + [target], timeout=timeout)

    elif name == "masscan_scan":
        target = arguments["target"]
        if err := validate_ip(target):
            return [TextContent(type="text", text=err)]
        ports = arguments.get("ports", "1-1000")
        rate = int(arguments.get("rate", 1000))
        result = exec_in_toolchain(
            ["masscan", target, "-p", ports, "--rate", str(rate), "--output-format", "list"],
            timeout=600,
        )

    else:
        result = mcp_error("unknown_tool", name)

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
