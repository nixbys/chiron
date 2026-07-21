# routes/toolchain_routes.py
"""Status/visibility routes for the local-vs-container toolchain execution mode.

See mcp_servers/common.py (_resolve_exec_mode, _exec_local, _exec_container)
for the mechanism this reports on.
"""
import shutil

from fastapi import APIRouter, Request

from core.middleware import require_admin
from mcp_servers.common import _resolve_exec_mode

router = APIRouter(prefix="/api/toolchain", tags=["toolchain"])

# The binaries the 6 toolchain-backed MCP servers shell out to today
# (recon, osint, web_vuln, hashcrack, yara, exploit — see README "Hybrid /
# local-tools mode"). Kept as a flat list here rather than importing each
# server module, since the servers are MCP stdio entrypoints, not meant to
# be imported by the main app process.
_KNOWN_BINARIES = [
    "nmap", "masscan",
    "theHarvester", "sherlock", "dig", "whois", "amass",
    "nikto", "gobuster", "sqlmap", "nuclei", "ffuf",
    "hashid", "john",
    "yara",
    "searchsploit",
]


def setup_toolchain_routes():
    """Setup toolchain execution-mode status routes."""

    @router.get("/exec-modes")
    def exec_modes(request: Request):
        """Report the resolved local/container mode for each known toolchain
        binary, and — for binaries resolved to "local" — whether they were
        actually found on PATH."""
        require_admin(request)
        modes = []
        for binary in _KNOWN_BINARIES:
            mode = _resolve_exec_mode(binary)
            entry = {"binary": binary, "mode": mode}
            if mode == "local":
                found = shutil.which(binary)
                entry["installed"] = found is not None
                entry["path"] = found
            modes.append(entry)
        return {"binaries": modes}

    return router
