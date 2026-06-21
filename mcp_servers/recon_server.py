"""
recon_server.py

MCP server for network reconnaissance tools (nmap, masscan).
All scans are executed inside the odysseus-toolchain sidecar container.
The caller is responsible for obtaining written authorization before targeting any host.
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

server = Server("recon")

_TOOLCHAIN_API = os.environ.get("ODYSSEUS_TOOLCHAIN_API", "http://odysseus-toolchain:8088")

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
                "ports": {"type": "string", "description": "Port range, e.g. '1-65535' or '80,443,8080'", "default": "1-1000"},
                "rate": {"type": "integer", "description": "Packets per second", "default": 1000},
            },
            "required": ["target"],
        },
    ),
]


def _exec_in_toolchain(cmd: list[str], timeout: int = 300) -> str:
    """Call the toolchain exec API and return combined stdout+stderr."""
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
        return f"[timeout] Scan exceeded {timeout}s and was terminated."
    except Exception as exc:  # noqa: BLE001
        return f"[error] {exc}"


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "nmap_scan":
        target = arguments["target"]
        flags = arguments.get("flags", "-sV -T4 --open").split()
        timeout = int(arguments.get("timeout", 300))
        output = _exec_in_toolchain(["nmap"] + flags + [target], timeout=timeout)
        return [TextContent(type="text", text=output)]

    if name == "masscan_scan":
        target = arguments["target"]
        ports = arguments.get("ports", "1-1000")
        rate = int(arguments.get("rate", 1000))
        output = _exec_in_toolchain(
            ["masscan", target, "-p", ports, "--rate", str(rate), "--output-format", "list"],
            timeout=600,
        )
        return [TextContent(type="text", text=output)]

    return [TextContent(type="text", text=f"[error] Unknown tool: {name}")]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
