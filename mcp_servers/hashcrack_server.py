"""
hashcrack_server.py

MCP server for password hash identification and offline cracking.
Runs inside the odysseus-toolchain sidecar. Authorized assessment use only.
"""

import asyncio
import re
import sys
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import exec_in_toolchain, mcp_error

server = Server("hashcrack")

# Allowlist of safe wordlist paths inside toolchain container
_WORDLIST_ALLOWLIST = {
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirb/big.txt",
    "/usr/share/wordlists/fasttrack.txt",
}

_HASH_RE = re.compile(r"^[a-fA-F0-9$./]{8,}$")

TOOLS = [
    Tool(
        name="identify_hash",
        description="Identify the hash type of a given hash string using hashid.",
        inputSchema={
            "type": "object",
            "properties": {
                "hash": {"type": "string", "description": "Hash string to identify"}
            },
            "required": ["hash"],
        },
    ),
    Tool(
        name="john_crack",
        description=(
            "Attempt to crack a hash file using John the Ripper with a wordlist. "
            "Hash file must exist inside the toolchain container at /workspaces/<filename>."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "hash_file": {
                    "type": "string",
                    "description": "Filename under /workspaces/ in toolchain (no path traversal)",
                },
                "wordlist": {
                    "type": "string",
                    "default": "/usr/share/wordlists/rockyou.txt",
                },
                "format": {
                    "type": "string",
                    "description": "John format string (optional, e.g. 'md5crypt')",
                },
                "timeout": {"type": "integer", "default": 120},
            },
            "required": ["hash_file"],
        },
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "identify_hash":
        h = arguments["hash"]
        if not _HASH_RE.match(h.strip()):
            return [TextContent(type="text", text=mcp_error("invalid_hash", "Input does not look like a hash string"))]
        result = exec_in_toolchain(["hashid", h.strip()], timeout=10)

    elif name == "john_crack":
        # Block path traversal in hash_file
        raw = arguments["hash_file"]
        if "/" in raw or ".." in raw:
            return [TextContent(type="text", text=mcp_error("invalid_path", "hash_file must be a plain filename, not a path"))]
        hash_file = f"/workspaces/{raw}"

        wordlist = arguments.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        if wordlist not in _WORDLIST_ALLOWLIST:
            return [TextContent(type="text", text=mcp_error("invalid_wordlist", f"Wordlist must be one of: {sorted(_WORDLIST_ALLOWLIST)}"))]

        timeout = int(arguments.get("timeout", 120))
        cmd = ["john", hash_file, f"--wordlist={wordlist}"]
        if fmt := arguments.get("format"):
            cmd.append(f"--format={fmt}")
        crack_out = exec_in_toolchain(cmd, timeout=timeout)
        show_out = exec_in_toolchain(["john", hash_file, "--show"], timeout=10)
        result = f"[crack]\n{crack_out}\n\n[cracked passwords]\n{show_out}"

    else:
        result = mcp_error("unknown_tool", name)

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
