"""
hashcrack_server.py

MCP server for password hash identification and cracking using hashid, john, and hashcat.
Runs inside the odysseus-toolchain sidecar. For authorized CTF/assessment use only.
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

server = Server("hashcrack")

_TOOLCHAIN_API = os.environ.get("ODYSSEUS_TOOLCHAIN_API", "http://odysseus-toolchain:8088")

TOOLS = [
    Tool(
        name="identify_hash",
        description="Identify the hash type of a given hash string using hashid.",
        inputSchema={
            "type": "object",
            "properties": {"hash": {"type": "string", "description": "Hash string to identify"}},
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
                "hash_file": {"type": "string", "description": "Filename under /workspaces/ in toolchain"},
                "wordlist": {
                    "type": "string",
                    "default": "/usr/share/wordlists/rockyou.txt",
                },
                "format": {"type": "string", "description": "John format string (optional, e.g. 'md5crypt')"},
                "timeout": {"type": "integer", "default": 120},
            },
            "required": ["hash_file"],
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
    if name == "identify_hash":
        result = _exec(["hashid", arguments["hash"]], timeout=10)

    elif name == "john_crack":
        hash_file = f"/workspaces/{arguments['hash_file']}"
        wordlist = arguments.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        timeout = int(arguments.get("timeout", 120))
        cmd = ["john", hash_file, f"--wordlist={wordlist}"]
        if fmt := arguments.get("format"):
            cmd.append(f"--format={fmt}")
        result = _exec(cmd, timeout=timeout)
        # Also show cracked passwords
        show_result = _exec(["john", hash_file, "--show"], timeout=10)
        result = f"[crack]\n{result}\n\n[cracked]\n{show_result}"

    else:
        result = f"[error] Unknown tool: {name}"

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
