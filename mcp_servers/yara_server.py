"""
yara_server.py

MCP server for YARA-based malware detection and rule management.
Scans run inside the odysseus-toolchain sidecar using the yara binary.
Rule files are read from /workspaces/yara_rules/ inside the container.
"""

import asyncio
import sys
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import exec_in_toolchain, mcp_error

server = Server("yara")

_RULES_DIR = "/workspaces/yara_rules"
_SCAN_DIR = "/workspaces"

TOOLS = [
    Tool(
        name="yara_scan",
        description=(
            "Scan a file or directory inside the toolchain container against YARA rules. "
            "Target must be under /workspaces/. Rules are loaded from /workspaces/yara_rules/ "
            "or a specific rule file can be provided."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "File or directory to scan (relative to /workspaces/)",
                },
                "rule_file": {
                    "type": "string",
                    "description": "Specific .yar rule file (relative to /workspaces/yara_rules/). "
                                   "Omit to scan with all rules in the rules directory.",
                    "default": "",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Scan directories recursively",
                    "default": True,
                },
                "timeout": {"type": "integer", "default": 120},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="yara_rule_write",
        description=(
            "Write a YARA rule file to /workspaces/yara_rules/<name>.yar in the toolchain container. "
            "Use this to create custom detection rules for your engagement."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Rule set name (alphanumeric + underscores only, no extension)",
                },
                "content": {
                    "type": "string",
                    "description": "Full YARA rule content",
                },
            },
            "required": ["name", "content"],
        },
    ),
    Tool(
        name="yara_list_rules",
        description="List all YARA rule files available in /workspaces/yara_rules/.",
        inputSchema={"type": "object", "properties": {}},
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "yara_scan":
        raw_target = arguments["target"]
        # Prevent path traversal outside /workspaces
        if ".." in raw_target or raw_target.startswith("/"):
            return [TextContent(type="text", text=mcp_error("invalid_path", "Target must be a relative path under /workspaces/"))]
        target = f"{_SCAN_DIR}/{raw_target}"

        rule_file = arguments.get("rule_file", "")
        recursive = arguments.get("recursive", True)
        timeout = int(arguments.get("timeout", 120))

        if rule_file:
            if ".." in rule_file or rule_file.startswith("/"):
                return [TextContent(type="text", text=mcp_error("invalid_path", "rule_file must be relative to /workspaces/yara_rules/"))]
            rules_arg = f"{_RULES_DIR}/{rule_file}"
        else:
            rules_arg = _RULES_DIR

        cmd = ["yara", "-w"]
        if recursive:
            cmd.append("-r")
        cmd += [rules_arg, target]
        result = exec_in_toolchain(cmd, timeout=timeout)

    elif name == "yara_rule_write":
        rule_name = arguments["name"]
        if not rule_name.replace("_", "").isalnum():
            return [TextContent(type="text", text=mcp_error("invalid_name", "Rule name must be alphanumeric and underscores only"))]
        content = arguments["content"]
        # Write via mkdir + tee through stdin
        mkdir_out = exec_in_toolchain(["mkdir", "-p", _RULES_DIR], timeout=5)
        write_out = exec_in_toolchain(
            ["tee", f"{_RULES_DIR}/{rule_name}.yar"],
            stdin=content,
            timeout=10,
        )
        result = f"Written {_RULES_DIR}/{rule_name}.yar\n{write_out}"

    elif name == "yara_list_rules":
        result = exec_in_toolchain(["ls", "-la", _RULES_DIR], timeout=5)

    else:
        result = mcp_error("unknown_tool", name)

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
