#!/usr/bin/env python3
"""mcp_health_check.py — verify every built-in MCP server actually round-trips.

Upstream Odysseus has open reports of MCP servers intermittently failing to
register or become callable in chat/agent sessions, with tools "disappearing"
silently rather than raising a visible error. Since Odysseus Red's headline
differentiator is its 14 cybersecurity MCP servers (plus 4 core-platform
servers: email, memory, image_gen, rag), a registration failure in any one of
them needs to be loud and specific, not discovered by a user mid-session.

This script speaks the real MCP stdio protocol to each server script directly
(spawn -> initialize -> list_tools), independent of whether the server is
registered in the running app's own MCP-server database table. It does NOT
call any tool (that would require live API keys, the Kali toolchain sidecar,
and network egress) -- it only confirms the server process starts cleanly and
correctly advertises its tools, which is exactly the failure mode reported
upstream.

Usage:
    python scripts/mcp_health_check.py            # human-readable report
    python scripts/mcp_health_check.py --json      # machine-readable, for CI
    python scripts/mcp_health_check.py --timeout 20

Exit code is non-zero if any server fails to initialize or list tools within
the timeout -- suitable as a CI gate or a pre-release check.
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The 14 cybersecurity-focused MCP servers unique to this fork, plus the 4
# core-platform servers Odysseus Red also ships as built-ins. Kept as an
# explicit list (rather than globbing mcp_servers/*.py) so a newly added
# server file that hasn't been wired up yet doesn't silently count as a
# "failure" here, and so this list itself documents what's expected to exist.
FORK_SECURITY_SERVERS = [
    "recon_server", "intel_server", "osint_server", "web_vuln_server",
    "hashcrack_server", "spiderfoot_server", "pdf_server", "yara_server",
    "exploit_server", "transform_server", "asset_server", "attck_server",
    "risk_server", "findings_server",
]
CORE_SERVERS = ["email_server", "memory_server", "image_gen_server", "rag_server"]


async def check_server(name: str, timeout: float) -> dict:
    """Spawn one MCP server via stdio and confirm initialize + list_tools."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    script = REPO_ROOT / "mcp_servers" / f"{name}.py"
    if not script.exists():
        return {"server": name, "ok": False, "error": f"missing file: {script}"}

    params = StdioServerParameters(command=sys.executable, args=[str(script)], env=None)
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=timeout)
                result = await asyncio.wait_for(session.list_tools(), timeout=timeout)
                tool_names = sorted(t.name for t in result.tools)
                return {
                    "server": name,
                    "ok": True,
                    "tool_count": len(tool_names),
                    "tools": tool_names,
                }
    except asyncio.TimeoutError:
        return {"server": name, "ok": False, "error": f"timed out after {timeout}s"}
    except Exception as e:  # noqa: BLE001 -- report every failure mode, don't filter
        return {"server": name, "ok": False, "error": f"{type(e).__name__}: {e}"}


async def run_all(servers: list[str], timeout: float) -> list[dict]:
    return await asyncio.gather(*(check_server(name, timeout) for name in servers))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--timeout", type=float, default=15.0, help="per-server timeout in seconds")
    parser.add_argument(
        "--core-only", action="store_true", help="check only the 4 core-platform servers"
    )
    parser.add_argument(
        "--security-only", action="store_true", help="check only the 14 security-focused servers"
    )
    args = parser.parse_args()

    if args.core_only:
        servers = CORE_SERVERS
    elif args.security_only:
        servers = FORK_SECURITY_SERVERS
    else:
        servers = FORK_SECURITY_SERVERS + CORE_SERVERS

    results = asyncio.run(run_all(servers, args.timeout))
    failures = [r for r in results if not r["ok"]]

    if args.json:
        print(json.dumps({"results": results, "failures": len(failures)}, indent=2))
    else:
        for r in sorted(results, key=lambda x: x["server"]):
            if r["ok"]:
                print(f"  OK  {r['server']:<20} {r['tool_count']} tools: {', '.join(r['tools'])}")
            else:
                print(f"FAIL  {r['server']:<20} {r['error']}")
        print()
        print(f"{len(results) - len(failures)}/{len(results)} MCP servers round-tripped cleanly.")
        if failures:
            print(f"{len(failures)} FAILED: {', '.join(f['server'] for f in failures)}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
