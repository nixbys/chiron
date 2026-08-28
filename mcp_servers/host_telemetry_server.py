"""
host_telemetry_server.py

MCP server for defensive host telemetry: running processes, listening
sockets, logged-in users, cron jobs, and installed packages. The blue-team
complement to recon_server.py's offensive scanning -- read-only
introspection of *this* host, not an arbitrary target.

Important scope caveat: this reports on the host/container the Odysseus
app itself is running in, not on a pentest target. The Kali toolchain
sidecar (docker/toolchain/, see ADR 001) is a disposable attack-tool
container -- querying its own process list would be useless for defensive
monitoring of anything real, so unlike every other server in this
directory, tools here never call exec_in_toolchain(). Everything runs
via `psutil` (pure Python, in-process) directly against the container
Odysseus itself is running in. If Odysseus runs inside a Docker container
(the default deployment), that means these tools only ever see the
container's own namespace -- not the true underlying host -- since no
host-namespace passthrough (bind-mounted /proc, `pid: host`, etc.) exists
in this fork yet. `docker/host-docker.yml`'s Docker-socket passthrough is
a different kind of access (control plane, not process/socket visibility)
and doesn't help here. True host-level visibility from inside a container
is a real gap, left for a future pass rather than solved in this one.

cron/package introspection additionally only works on Linux (both are
read via stdlib `subprocess` against `crontab`/`dpkg`/`rpm`, not psutil,
which has no cross-platform API for either) -- both tools return a clear
`unsupported_platform` error elsewhere.
"""

import asyncio
import platform
import subprocess  # nosec B404 -- read-only introspection commands with fixed argv, no shell, no user input
import sys
from pathlib import Path

import psutil

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import mcp_error

server = Server("host_telemetry")

_IS_LINUX = platform.system() == "Linux"
_SUBPROCESS_TIMEOUT = 10


def _processes_fetch(limit: int = 200) -> dict:
    """List running processes (pid/name/user/cmdline). Best-effort per
    process -- a process that exits mid-iteration or denies access to one
    field just gets partial info, never aborts the whole listing."""
    try:
        procs = []
        for p in psutil.process_iter(["pid", "name", "username", "cmdline"]):
            info = p.info
            procs.append({
                "pid": info.get("pid"),
                "name": info.get("name") or "",
                "user": info.get("username") or "",
                "cmdline": " ".join(info.get("cmdline") or [])[:200],
            })
        procs.sort(key=lambda x: x["pid"] or 0)
        return {"processes": procs[:limit]}
    except Exception as exc:  # noqa: BLE001
        return {"_mcp_error": str(exc)}


def _processes_format(data: dict) -> str:
    procs = data["processes"]
    if not procs:
        return "No processes found."
    lines = [f"{'PID':<8} {'User':<16} {'Name':<24} Cmdline"]
    lines.append("-" * 100)
    for p in procs:
        lines.append(f"{p['pid'] or '':<8} {p['user']:<16} {p['name']:<24} {p['cmdline']}")
    return "\n".join(lines)


def _listening_ports_fetch() -> dict:
    """List TCP/UDP sockets in LISTEN state, with owning pid where visible."""
    try:
        listening = []
        for c in psutil.net_connections(kind="inet"):
            if c.status != psutil.CONN_LISTEN:
                continue
            laddr = c.laddr
            listening.append({
                "proto": "tcp" if c.type == 1 else "udp",  # SOCK_STREAM=1, SOCK_DGRAM=2
                "address": getattr(laddr, "ip", "") or "",
                "port": getattr(laddr, "port", None),
                "pid": c.pid,
            })
        listening.sort(key=lambda x: x["port"] or 0)
        return {"listening": listening}
    except psutil.AccessDenied as exc:
        return {"_mcp_error": f"access denied -- some sockets need elevated privileges to inspect: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"_mcp_error": str(exc)}


def _listening_ports_format(data: dict) -> str:
    listening = data["listening"]
    if not listening:
        return "No listening sockets found."
    lines = [f"{'Proto':<6} {'Address':<20} {'Port':<8} PID"]
    lines.append("-" * 50)
    for c in listening:
        lines.append(f"{c['proto']:<6} {c['address']:<20} {c['port'] or '':<8} {c['pid'] or ''}")
    return "\n".join(lines)


def _users_fetch() -> dict:
    """List currently logged-in users (interactive sessions)."""
    try:
        return {"users": [
            {
                "name": u.name,
                "terminal": u.terminal or "",
                "host": u.host or "",
                "started": u.started,
            }
            for u in psutil.users()
        ]}
    except Exception as exc:  # noqa: BLE001
        return {"_mcp_error": str(exc)}


def _users_format(data: dict) -> str:
    import time
    users = data["users"]
    if not users:
        return "No logged-in users found."
    lines = [f"{'User':<16} {'Terminal':<12} {'Host':<20} Since"]
    lines.append("-" * 70)
    for u in users:
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(u["started"])) if u["started"] else ""
        lines.append(f"{u['name']:<16} {u['terminal']:<12} {u['host']:<20} {stamp}")
    return "\n".join(lines)


def _cron_fetch() -> dict:
    """List the invoking user's crontab plus system-wide cron.d drop-ins.
    Linux-only -- crontab's own storage format/location isn't portable."""
    if not _IS_LINUX:
        return {"_mcp_error": mcp_error("unsupported_platform", "cron introspection is Linux-only")}
    entries: list[str] = []
    try:
        result = subprocess.run(  # nosec B603 B607 -- fixed argv, no shell, read-only
            ["crontab", "-l"], capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT,
        )
        if result.returncode == 0:
            entries.extend(
                line for line in result.stdout.splitlines()
                if line.strip() and not line.strip().startswith("#")
            )
    except FileNotFoundError:
        pass  # crontab binary not installed -- fall through to cron.d
    except Exception as exc:  # noqa: BLE001
        return {"_mcp_error": str(exc)}

    for cron_dir in (Path("/etc/cron.d"), Path("/etc/crontab")):
        try:
            if cron_dir.is_file():
                entries.extend(
                    line for line in cron_dir.read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip() and not line.strip().startswith("#")
                )
            elif cron_dir.is_dir():
                for f in sorted(cron_dir.glob("*")):
                    if f.is_file():
                        entries.extend(
                            f"[{f.name}] {line}"
                            for line in f.read_text(encoding="utf-8", errors="replace").splitlines()
                            if line.strip() and not line.strip().startswith("#")
                        )
        except (PermissionError, OSError):
            continue  # not readable -- best-effort, skip rather than fail the whole listing

    return {"entries": sorted(set(entries))}


def _cron_format(data: dict) -> str:
    entries = data["entries"]
    return "\n".join(entries) if entries else "No cron entries found."


def _packages_fetch() -> dict:
    """List installed OS packages via dpkg (Debian/Kali/Ubuntu) or rpm
    (RHEL/Fedora), whichever is present. Linux-only."""
    if not _IS_LINUX:
        return {"_mcp_error": mcp_error("unsupported_platform", "package introspection is Linux-only")}

    for cmd, parse in (
        (["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], lambda line: line.split("\t", 1)),
        (["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], lambda line: line.split("\t", 1)),
    ):
        try:
            result = subprocess.run(  # nosec B603 -- fixed argv, no shell, read-only
                cmd, capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT,
            )
        except FileNotFoundError:
            continue
        except Exception as exc:  # noqa: BLE001
            return {"_mcp_error": str(exc)}
        if result.returncode != 0:
            continue
        packages = []
        for line in result.stdout.splitlines():
            parts = parse(line)
            if len(parts) == 2:
                packages.append({"name": parts[0].strip(), "version": parts[1].strip()})
        return {"packages": sorted(packages, key=lambda p: p["name"])}

    return {"_mcp_error": mcp_error("not_found", "neither dpkg-query nor rpm is available on this host")}


def _packages_format(data: dict) -> str:
    packages = data["packages"]
    if not packages:
        return "No packages found."
    lines = [f"{'Package':<40} Version"]
    lines.append("-" * 70)
    for p in packages:
        lines.append(f"{p['name']:<40} {p['version']}")
    return "\n".join(lines)


TOOLS = [
    Tool(
        name="host_processes",
        description="List running processes on the host Odysseus itself is running in (pid, name, user, cmdline). Container-scoped -- see module docstring.",
        inputSchema={
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 200, "description": "Max processes to return"}},
        },
    ),
    Tool(
        name="host_listening_ports",
        description="List TCP/UDP sockets in LISTEN state on the host Odysseus itself is running in, with owning pid where visible. Container-scoped -- see module docstring.",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="host_users",
        description="List currently logged-in users (interactive sessions) on the host Odysseus itself is running in.",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="host_cron_jobs",
        description="List the invoking user's crontab plus system cron.d entries. Linux-only.",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="host_packages",
        description="List installed OS packages (dpkg or rpm, whichever is present). Linux-only.",
        inputSchema={"type": "object", "properties": {}},
    ),
]

_FETCH_FORMAT = {
    "host_processes": (_processes_fetch, _processes_format),
    "host_listening_ports": (_listening_ports_fetch, _listening_ports_format),
    "host_users": (_users_fetch, _users_format),
    "host_cron_jobs": (_cron_fetch, _cron_format),
    "host_packages": (_packages_fetch, _packages_format),
}


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        fetch_format = _FETCH_FORMAT.get(name)
        if not fetch_format:
            result = mcp_error("unknown_tool", name)
        else:
            fetch, fmt = fetch_format
            if name == "host_processes":
                data = fetch(int(arguments.get("limit", 200)))
            else:
                data = fetch()
            if "_mcp_error" in data:
                # Some fetch fns (unsupported_platform/not_found) already
                # return a fully-formatted "[error:code] ..." string; others
                # (a raw exception message) don't -- wrap only the latter so
                # we never double-wrap.
                msg = data["_mcp_error"]
                result = msg if msg.startswith("[error:") else mcp_error("error", msg)
            else:
                result = fmt(data)
    except Exception as exc:  # noqa: BLE001
        result = mcp_error("error", str(exc))

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
