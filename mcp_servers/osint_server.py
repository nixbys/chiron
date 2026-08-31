"""
osint_server.py

MCP server for passive OSINT collection: theHarvester, Sherlock (username search),
DNS enumeration, WHOIS, and Amass subdomain discovery.
All tools run inside the odysseus-toolchain sidecar.
"""

import asyncio
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import (
    SCOPE_ARG_PROPERTIES,
    check_scope_from_args,
    exec_in_toolchain,
    mcp_error,
    validate_domain,
)

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
                **SCOPE_ARG_PROPERTIES,
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
                **SCOPE_ARG_PROPERTIES,
            },
            "required": ["domain"],
        },
    ),
    Tool(
        name="whois_lookup",
        description="Perform a WHOIS lookup on a domain or IP address.",
        inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string"}, **SCOPE_ARG_PROPERTIES},
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
                **SCOPE_ARG_PROPERTIES,
            },
            "required": ["domain"],
        },
    ),
    Tool(
        name="secrets_scan",
        description=(
            "Clone a git repository and scan its full history for leaked credentials/API "
            "keys/tokens (gitleaks) -- a standard pentest/OSINT deliverable. Matched secret "
            "values are redacted in the output, never shown in full."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "repo_url": {
                    "type": "string",
                    "description": "Git URL to clone, e.g. https://github.com/org/repo.git or git@github.com:org/repo.git",
                },
                "timeout": {"type": "integer", "default": 180},
                **SCOPE_ARG_PROPERTIES,
            },
            "required": ["repo_url"],
        },
    ),
]

# Fixed, non-user-controlled scratch path -- every call clones into (and
# first rm -rf's) this exact directory rather than a per-call unique name,
# so no cleanup-on-error bookkeeping is needed and there's no path built
# from user input anywhere in the rm/git argv. Trade-off: concurrent
# secrets_scan calls clobber each other's checkout -- acceptable for a
# one-shot analyst tool, same "small, focused, no queueing" scope as
# msf_server's read-only search.
_SECRETS_SCAN_WORKDIR = "/workspaces/secrets_scan_repo"

# An http(s):// URL, or SCP-like git@host:path -- and never starting with
# "-", which would otherwise let a crafted repo_url be interpreted as a
# `git clone` flag (e.g. "--upload-pack=...") instead of a URL argument.
_GIT_URL_RE = re.compile(r"^(?:https?://[^\s]+|[\w.-]+@[\w.-]+:[^\s]+)$")


def _git_repo_host(repo_url: str) -> str | None:
    """Best-effort hostname extraction for check_scope() -- cloning FROM a
    remote host is exactly the kind of network-reaching action scope
    enforcement exists for, even though the "tool" here is git, not one of
    the usual scan binaries."""
    if repo_url.startswith(("http://", "https://")):
        return urlparse(repo_url).hostname
    m = re.match(r"^[\w.-]+@([\w.-]+):", repo_url)
    return m.group(1) if m else None


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "harvester":
        domain = arguments["domain"]
        if err := validate_domain(domain):
            return [TextContent(type="text", text=err)]
        if err := check_scope_from_args(arguments, domain, "harvester"):
            return [TextContent(type="text", text=err)]
        sources = arguments.get("sources", "bing,google,dnsdumpster,crtsh")
        limit = str(arguments.get("limit", 200))
        result = exec_in_toolchain(
            ["theHarvester", "-d", domain, "-b", sources, "-l", limit],
            timeout=180,
            engagement_id=arguments.get("engagement_id"),
        )

    elif name == "username_search":
        username = arguments["username"]
        timeout = int(arguments.get("timeout", 60))
        result = exec_in_toolchain(["sherlock", username, "--print-found"], timeout=timeout)

    elif name == "dns_enum":
        domain = arguments["domain"]
        if err := validate_domain(domain):
            return [TextContent(type="text", text=err)]
        if err := check_scope_from_args(arguments, domain, "dns_enum"):
            return [TextContent(type="text", text=err)]
        record_types = arguments.get("record_types", "A MX NS TXT CNAME SOA").split()
        lines = []
        for rtype in record_types:
            out = exec_in_toolchain(["dig", "+short", rtype, domain], timeout=10, engagement_id=arguments.get("engagement_id"))
            lines.append(f"[{rtype}]\n{out}")
        result = "\n\n".join(lines)

    elif name == "whois_lookup":
        target = arguments["target"]
        if err := check_scope_from_args(arguments, target, "whois_lookup"):
            return [TextContent(type="text", text=err)]
        result = exec_in_toolchain(["whois", target], timeout=30, engagement_id=arguments.get("engagement_id"))

    elif name == "subdomain_enum":
        domain = arguments["domain"]
        if err := validate_domain(domain):
            return [TextContent(type="text", text=err)]
        if err := check_scope_from_args(arguments, domain, "subdomain_enum"):
            return [TextContent(type="text", text=err)]
        passive = arguments.get("passive", True)
        timeout = int(arguments.get("timeout", 120))
        cmd = ["amass", "enum", "-d", domain, "-silent"]
        if passive:
            cmd.append("-passive")
        result = exec_in_toolchain(cmd, timeout=timeout, engagement_id=arguments.get("engagement_id"))

    elif name == "secrets_scan":
        repo_url = arguments["repo_url"].strip()
        if not _GIT_URL_RE.match(repo_url):
            return [TextContent(type="text", text=mcp_error(
                "invalid_repo_url",
                "repo_url must be an http(s):// URL or an SCP-like git@host:path address (and must not start with '-')",
            ))]
        host = _git_repo_host(repo_url)
        if host and (err := check_scope_from_args(arguments, host, "secrets_scan")):
            return [TextContent(type="text", text=err)]
        timeout = int(arguments.get("timeout", 180))
        engagement_id = arguments.get("engagement_id")

        # Fixed workdir (see _SECRETS_SCAN_WORKDIR) -- always cleared first
        # so a stale checkout from a prior call/crash never mixes into this
        # scan's results.
        exec_in_toolchain(["rm", "-rf", _SECRETS_SCAN_WORKDIR], timeout=15, engagement_id=engagement_id)
        clone_out = exec_in_toolchain(
            ["git", "clone", "--depth", "1", repo_url, _SECRETS_SCAN_WORKDIR],
            timeout=timeout, engagement_id=engagement_id,
        )
        if clone_out.startswith("[error:"):
            result = clone_out
        else:
            scan_out = exec_in_toolchain(
                ["gitleaks", "detect", "--source", _SECRETS_SCAN_WORKDIR, "--no-banner", "--redact", "-v"],
                timeout=timeout, engagement_id=engagement_id,
            )
            result = f"[git clone]\n{clone_out}\n\n[gitleaks]\n{scan_out}"

    else:
        result = mcp_error("unknown_tool", name)

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
