"""
msf_server.py

MCP server for Metasploit Framework module search/info -- read-only in
this phase. `msfconsole`/`msfvenom` are already installed in the Kali
toolchain sidecar and already allowlisted in docker/toolchain/exec_api.py's
ALLOWED_BINARIES, but had no MCP server driving them until now (confirmed
dead code path).

Deliberately read-only module search/info only: no RPC daemon, no
session-driven exploit execution or payload delivery. That's materially
riskier (listener management, live sessions against real hosts) and
belongs in its own design pass once this foundation is proven, not bundled
in here. Both tools run one-shot via `msfconsole -q -x "<cmds>; exit"`,
same pattern as any other one-shot CLI binary in the sidecar.

Neither tool takes a network target (a module name/search term isn't a
host), so neither calls mcp_servers/common.py's check_scope() -- but both
still get exec_in_toolchain()'s standard audit logging for free, which is
the point of building on that one chokepoint.
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

server = Server("msf")

# Module names are Metasploit's own path-like identifiers (e.g.
# "exploit/windows/smb/ms17_010_eternalblue") -- restrict to the charset
# msfconsole itself accepts rather than passing an arbitrary string
# straight into a shell-interpolated `-x` command string.
_MODULE_RE = re.compile(r"^[A-Za-z0-9_/\.\-]{1,200}$")

TOOLS = [
    Tool(
        name="msf_search",
        description=(
            "Search Metasploit Framework modules (exploits, auxiliary, post, payloads) "
            "by keyword, CVE ID, platform, or type. Read-only -- does not run any module."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search terms, e.g. 'type:exploit platform:windows smb' or 'CVE-2017-0144'",
                },
                "timeout": {"type": "integer", "default": 60},
            },
            "required": ["query"],
        },
    ),
    Tool(
        name="msf_module_info",
        description=(
            "Show full details (description, targets, options, references) for one "
            "Metasploit module by its full path name. Read-only -- does not run the module."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "module": {
                    "type": "string",
                    "description": "Full module path, e.g. 'exploit/windows/smb/ms17_010_eternalblue'",
                },
                "timeout": {"type": "integer", "default": 60},
            },
            "required": ["module"],
        },
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "msf_search":
        query = arguments["query"].strip()
        if not query:
            return [TextContent(type="text", text=mcp_error("invalid_query", "query must not be empty"))]
        # exec_in_toolchain runs this as an argv list, not through a shell,
        # so there's no shell-injection risk -- but `query` is interpolated
        # into the -x argument, which msfconsole's own REPL splits on `;`/
        # newline into separate commands. Without this check, a query like
        # "smb; use exploit/...; exploit" would chain and run a *real*
        # module through the "read-only search" tool -- reject any query
        # that could break out of the single `search ...` command.
        if ";" in query or "\n" in query:
            return [TextContent(type="text", text=mcp_error(
                "invalid_query", "query may not contain ';' or a newline",
            ))]
        timeout = int(arguments.get("timeout", 60))
        result = exec_in_toolchain(
            ["msfconsole", "-q", "-x", f"search {query}; exit"],
            timeout=timeout,
        )

    elif name == "msf_module_info":
        module = arguments["module"].strip()
        if not _MODULE_RE.match(module):
            return [TextContent(type="text", text=mcp_error(
                "invalid_module",
                f"{module!r} is not a valid module path (e.g. 'exploit/windows/smb/ms17_010_eternalblue')",
            ))]
        timeout = int(arguments.get("timeout", 60))
        result = exec_in_toolchain(
            ["msfconsole", "-q", "-x", f"info {module}; exit"],
            timeout=timeout,
        )

    else:
        result = mcp_error("unknown_tool", name)

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
