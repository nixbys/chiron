"""
web_vuln_server.py

MCP server for web application assessment: nikto, gobuster, sqlmap, nuclei, ffuf.
All tools run inside the odysseus-toolchain sidecar. Authorized targets only.
"""

import asyncio
import sys
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import exec_in_toolchain, mcp_error, validate_url

server = Server("web_vuln")

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
                "extensions": {
                    "type": "string",
                    "description": "File extensions (e.g. php,html,txt)",
                    "default": "",
                },
                "threads": {"type": "integer", "default": 20},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="sqlmap_scan",
        description=(
            "Run sqlmap to detect SQL injection vulnerabilities on an authorized target URL. "
            "Non-destructive detection only by default (--level=1 --risk=1)."
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
    Tool(
        name="ffuf_fuzz",
        description=(
            "Fast web fuzzer (ffuf) for parameter, header, and path fuzzing against an authorized target. "
            "Use FUZZ as the placeholder in the URL."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL with FUZZ placeholder (e.g. http://target.com/FUZZ)",
                },
                "wordlist": {
                    "type": "string",
                    "default": "/usr/share/wordlists/dirb/common.txt",
                },
                "filter_code": {
                    "type": "string",
                    "description": "Comma-separated HTTP status codes to filter out (e.g. 404,403)",
                    "default": "404",
                },
                "threads": {"type": "integer", "default": 40},
                "timeout": {"type": "integer", "default": 300},
            },
            "required": ["url"],
        },
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "nikto_scan":
        url = arguments["url"]
        if err := validate_url(url):
            return [TextContent(type="text", text=err)]
        timeout = int(arguments.get("timeout", 300))
        result = exec_in_toolchain(["nikto", "-h", url, "-nointeractive"], timeout=timeout)

    elif name == "gobuster_dir":
        url = arguments["url"]
        if err := validate_url(url):
            return [TextContent(type="text", text=err)]
        wordlist = arguments.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        threads = str(arguments.get("threads", 20))
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", threads, "-q"]
        if ext := arguments.get("extensions", ""):
            cmd += ["-x", ext]
        result = exec_in_toolchain(cmd, timeout=600)

    elif name == "sqlmap_scan":
        url = arguments["url"]
        if err := validate_url(url):
            return [TextContent(type="text", text=err)]
        level = str(arguments.get("level", 1))
        risk = str(arguments.get("risk", 1))
        cmd = ["sqlmap", "-u", url, "--level", level, "--risk", risk,
               "--batch", "--output-dir=/tmp/sqlmap"]
        if data := arguments.get("data"):
            cmd += ["--data", data]
        result = exec_in_toolchain(cmd, timeout=600)

    elif name == "nuclei_scan":
        url = arguments["url"]
        if err := validate_url(url):
            return [TextContent(type="text", text=err)]
        severity = arguments.get("severity", "critical,high")
        timeout = int(arguments.get("timeout", 300))
        cmd = ["nuclei", "-u", url, "-severity", severity, "-silent"]
        if tags := arguments.get("tags"):
            cmd += ["-tags", tags]
        result = exec_in_toolchain(cmd, timeout=timeout)

    elif name == "ffuf_fuzz":
        url = arguments["url"]
        if "FUZZ" not in url:
            return [TextContent(type="text", text=mcp_error("invalid_url", "URL must contain the FUZZ placeholder"))]
        # Validate the base URL (strip FUZZ first)
        base = url.replace("FUZZ", "test")
        if err := validate_url(base):
            return [TextContent(type="text", text=err)]
        wordlist = arguments.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        fc = arguments.get("filter_code", "404")
        threads = str(arguments.get("threads", 40))
        timeout = int(arguments.get("timeout", 300))
        cmd = ["ffuf", "-u", url, "-w", wordlist, "-t", threads, "-fc", fc, "-s"]
        result = exec_in_toolchain(cmd, timeout=timeout)

    else:
        result = mcp_error("unknown_tool", name)

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
