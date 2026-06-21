"""
web_vuln_server.py

MCP server for web application assessment: nikto, gobuster (directory brute-force),
sqlmap (SQL injection detection), and nuclei (template-based vulnerability scanning).
All tools run inside the odysseus-toolchain sidecar. Authorized targets only.
"""

import asyncio
import os
import subprocess
import sys
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

server = Server("web_vuln")

TOOLCHAIN_CONTAINER = os.environ.get("ODYSSEUS_TOOLCHAIN_CONTAINER", "odysseus-toolchain")
_RUNTIME = os.environ.get("ODYSSEUS_CONTAINER_RUNTIME", "podman")

TOOLS = [
    Tool(
        name="nikto_scan",
        description=(
            "Run a nikto web server scan against an authorized target URL. "
            "Detects misconfigurations, outdated software, and common vulnerabilities."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full target URL (e.g. http://target.com)"},
                "timeout": {"type": "integer", "default": 300},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="gobuster_dir",
        description="Directory and file brute-force against an authorized web target using gobuster.",
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist inside toolchain container",
                    "default": "/usr/share/wordlists/dirb/common.txt",
                },
                "extensions": {"type": "string", "description": "File extensions (e.g. php,html,txt)", "default": ""},
                "threads": {"type": "integer", "default": 20},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="sqlmap_scan",
        description=(
            "Run sqlmap to detect SQL injection vulnerabilities on an authorized target URL. "
            "Uses non-destructive detection only by default (--level=1 --risk=1)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "data": {"type": "string", "description": "POST data string (optional)"},
                "level": {"type": "integer", "default": 1, "description": "1-5"},
                "risk": {"type": "integer", "default": 1, "description": "1-3"},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="nuclei_scan",
        description=(
            "Run nuclei template-based scanning against an authorized target. "
            "Optionally filter by severity or tag."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "severity": {
                    "type": "string",
                    "description": "Comma-separated severities (e.g. critical,high,medium)",
                    "default": "critical,high",
                },
                "tags": {"type": "string", "description": "Comma-separated template tags (optional)"},
                "timeout": {"type": "integer", "default": 300},
            },
            "required": ["url"],
        },
    ),
]


def _exec(cmd: list[str], timeout: int = 300) -> str:
    full_cmd = [_RUNTIME, "exec", TOOLCHAIN_CONTAINER] + cmd
    try:
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        out = (result.stdout or "") + (f"\n[stderr]\n{result.stderr}" if result.stderr else "")
        return out.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"[timeout] Command exceeded {timeout}s."
    except Exception as exc:  # noqa: BLE001
        return f"[error] {exc}"


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "nikto_scan":
        url = arguments["url"]
        timeout = int(arguments.get("timeout", 300))
        result = _exec(["nikto", "-h", url, "-nointeractive"], timeout=timeout)

    elif name == "gobuster_dir":
        url = arguments["url"]
        wordlist = arguments.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        threads = str(arguments.get("threads", 20))
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", threads, "-q"]
        ext = arguments.get("extensions", "")
        if ext:
            cmd += ["-x", ext]
        result = _exec(cmd, timeout=600)

    elif name == "sqlmap_scan":
        url = arguments["url"]
        level = str(arguments.get("level", 1))
        risk = str(arguments.get("risk", 1))
        cmd = ["sqlmap", "-u", url, "--level", level, "--risk", risk, "--batch", "--output-dir=/tmp/sqlmap"]
        if data := arguments.get("data"):
            cmd += ["--data", data]
        result = _exec(cmd, timeout=600)

    elif name == "nuclei_scan":
        url = arguments["url"]
        severity = arguments.get("severity", "critical,high")
        timeout = int(arguments.get("timeout", 300))
        cmd = ["nuclei", "-u", url, "-severity", severity, "-silent"]
        if tags := arguments.get("tags"):
            cmd += ["-tags", tags]
        result = _exec(cmd, timeout=timeout)

    else:
        result = f"[error] Unknown tool: {name}"

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
