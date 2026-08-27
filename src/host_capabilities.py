"""host_capabilities.py — detect tools/services already present on the host.

Odysseus Red is typically run inside a VM, and normally provisions its own
copies of several tools and services: the Kali toolchain binaries (nmap,
sqlmap, ...) and six sidecar services (Ollama, ChromaDB, SearXNG, SpiderFoot,
OpenSearch, BentoPDF). If the host (or the VM) already has one of these —
common on a pentest-focused VM image, or a machine that already runs Ollama
for other projects — provisioning a second copy is wasted resources at best.

This module implements a **scan, then verify, then ask** flow, deliberately
never scan-only:

  1. Scan  — cheap, read-only checks: is a binary on PATH, is a port open.
  2. Verify — for anything found, make a real call against it (a version
     flag, a health-check endpoint) before treating it as usable. "Something
     is listening on that port" is not the same claim as "the tool we expect
     is listening on that port" — for a security-focused project especially,
     trusting the former without confirming the latter is a confused-deputy
     risk, not just an edge case.
  3. Ask — never silently reuse a host resource. The caller decides per item
     whether to accept the reuse suggestion; nothing here writes to `.env`
     or changes behavior on its own.

Binary detection only works when this process itself is not containerized —
a container cannot see binaries installed on its host by design, container
isolation being the whole point. `running_in_container()` detects this so
callers can skip the (structurally meaningless) binary scan and print a
one-line explanation instead of a wall of false negatives. Service detection
still works from inside a container via `host.docker.internal` (already
wired up for the main `odysseus` service in docker-compose.yml's
`extra_hosts`), in addition to `localhost` for a native install.

Reusing a host service or binary trades away some of the isolation/
reproducibility a fresh VM or container would otherwise guarantee — see
`isolation_tradeoff_warning()`. That trade should be visible to whoever
accepts it, not papered over.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

try:
    import urllib.request
    import urllib.error
except ImportError:  # pragma: no cover — stdlib, always present
    urllib = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------

@dataclass
class BinaryCapability:
    """One toolchain binary this fork would otherwise run in the Kali sidecar."""
    name: str                      # canonical binary name, as invoked
    env_var: str                   # TOOLCHAIN_EXEC_MODE_<NAME> to set for reuse
    version_flags: tuple[str, ...] # flags tried in order until one produces output
    aliases: tuple[str, ...] = ()  # alternate command names to also try


@dataclass
class BinaryCheck:
    capability: BinaryCapability
    found: bool
    found_as: Optional[str] = None   # which name/alias actually resolved
    path: Optional[str] = None
    verified: bool = False
    detail: str = ""


@dataclass
class ServiceCapability:
    """One sidecar service this fork would otherwise provision a container for."""
    name: str
    port: int
    env_vars: tuple[str, ...]      # env var(s) to set for reuse, in .env
    compose_profile: str           # docker-compose.security.yml profile name
    verify: Callable[[str, int], tuple[bool, str]]  # (host, port) -> (ok, detail)


@dataclass
class ServiceCheck:
    capability: ServiceCapability
    found_at: Optional[str] = None   # "host:port" that responded, if any
    verified: bool = False
    detail: str = ""


@dataclass
class ScanResult:
    in_container: bool
    binaries: list[BinaryCheck] = field(default_factory=list)
    services: list[ServiceCheck] = field(default_factory=list)

    @property
    def reusable_binaries(self) -> list[BinaryCheck]:
        return [b for b in self.binaries if b.verified]

    @property
    def reusable_services(self) -> list[ServiceCheck]:
        return [s for s in self.services if s.verified]

    @property
    def has_anything_reusable(self) -> bool:
        return bool(self.reusable_binaries or self.reusable_services)


# ---------------------------------------------------------------------------
# Container-context detection
# ---------------------------------------------------------------------------

def running_in_container() -> bool:
    """Best-effort check for "is this process itself inside a container".

    `/.dockerenv` is the standard marker Docker/Podman write into every
    container's root filesystem. Not foolproof (a from-scratch image could
    omit it), but false negatives here only mean the binary scan runs and
    correctly finds nothing — never a false claim that a host tool exists.
    """
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup", "rt", encoding="utf-8") as f:
            content = f.read()
        return "docker" in content or "podman" in content or "kubepods" in content
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Toolchain binaries — the 16 with an existing TOOLCHAIN_EXEC_MODE_<NAME>
# per-tool override in .env.example (mcp_servers/common.py::_resolve_exec_mode).
# ---------------------------------------------------------------------------

TOOLCHAIN_BINARIES: tuple[BinaryCapability, ...] = (
    BinaryCapability("nmap", "TOOLCHAIN_EXEC_MODE_NMAP", ("--version",)),
    BinaryCapability("masscan", "TOOLCHAIN_EXEC_MODE_MASSCAN", ("--version",)),
    BinaryCapability(
        "theHarvester", "TOOLCHAIN_EXEC_MODE_THEHARVESTER", ("--version", "-h"),
        aliases=("theharvester",),
    ),
    BinaryCapability("sherlock", "TOOLCHAIN_EXEC_MODE_SHERLOCK", ("--version",)),
    BinaryCapability("dig", "TOOLCHAIN_EXEC_MODE_DIG", ("-v",)),
    BinaryCapability("whois", "TOOLCHAIN_EXEC_MODE_WHOIS", ("--version",)),
    BinaryCapability("amass", "TOOLCHAIN_EXEC_MODE_AMASS", ("-version",)),
    BinaryCapability("nikto", "TOOLCHAIN_EXEC_MODE_NIKTO", ("-Version", "-version")),
    BinaryCapability("gobuster", "TOOLCHAIN_EXEC_MODE_GOBUSTER", ("version",)),
    BinaryCapability("sqlmap", "TOOLCHAIN_EXEC_MODE_SQLMAP", ("--version",)),
    BinaryCapability("nuclei", "TOOLCHAIN_EXEC_MODE_NUCLEI", ("-version",)),
    BinaryCapability("ffuf", "TOOLCHAIN_EXEC_MODE_FFUF", ("-V",)),
    BinaryCapability("hashid", "TOOLCHAIN_EXEC_MODE_HASHID", ("--version",)),
    BinaryCapability("john", "TOOLCHAIN_EXEC_MODE_JOHN", ("--version",)),
    BinaryCapability("yara", "TOOLCHAIN_EXEC_MODE_YARA", ("--version",)),
    BinaryCapability("searchsploit", "TOOLCHAIN_EXEC_MODE_SEARCHSPLOIT", ("--version",)),
)


def _run_version_flag(binary_path: str, flag: str, timeout: float = 5.0) -> Optional[str]:
    """Run `<binary_path> <flag>` and return combined output if it produced
    any, else None. Deliberately ignores exit code: several of these tools
    (john, gobuster's `version` subcommand, nikto) exit non-zero or write to
    stderr on a successful version query depending on build. The bar here is
    "invoking this like a real CLI tool produces real CLI-tool-like output",
    which a stale/broken symlink or an unrelated file of the same name will
    not clear — that's the actual thing being verified, not an exact
    version string."""
    try:
        proc = subprocess.run(
            [binary_path, flag],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (proc.stdout or "") + (proc.stderr or "")
    return output.strip() or None


def check_binary(capability: BinaryCapability) -> BinaryCheck:
    names_to_try = (capability.name,) + capability.aliases
    for name in names_to_try:
        path = shutil.which(name)
        if path:
            for flag in capability.version_flags:
                output = _run_version_flag(path, flag)
                if output:
                    first_line = output.splitlines()[0][:120]
                    return BinaryCheck(
                        capability=capability, found=True, found_as=name,
                        path=path, verified=True, detail=first_line,
                    )
            return BinaryCheck(
                capability=capability, found=True, found_as=name, path=path,
                verified=False,
                detail=f"found on PATH but did not respond to {capability.version_flags} — not treated as usable",
            )
    return BinaryCheck(capability=capability, found=False, detail="not on PATH")


def scan_toolchain_binaries() -> list[BinaryCheck]:
    return [check_binary(c) for c in TOOLCHAIN_BINARIES]


# ---------------------------------------------------------------------------
# Services — the 6 sidecars in docker-compose.security.yml.
# ---------------------------------------------------------------------------

def _port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _http_get(url: str, timeout: float = 3.0) -> Optional[str]:
    if urllib is None:  # pragma: no cover
        return None
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # nosec B310 — noqa: S310 — url is always our own f"http://{host}:{port}{path}" built from the hardcoded SERVICES tuple + a fixed host allowlist (localhost / host.docker.internal), never user input
            return resp.read(4096).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None


def _verify_ollama(host: str, port: int) -> tuple[bool, str]:
    body = _http_get(f"http://{host}:{port}/api/version")
    if body and '"version"' in body:
        return True, body.strip()[:120]
    return False, "port open but /api/version did not look like Ollama"


def _verify_chromadb(host: str, port: int) -> tuple[bool, str]:
    for path in ("/api/v2/heartbeat", "/api/v1/heartbeat"):
        body = _http_get(f"http://{host}:{port}{path}")
        if body and ("nanosecond" in body or "heartbeat" in body.lower()):
            return True, f"{path} responded: {body.strip()[:100]}"
    return False, "port open but no ChromaDB heartbeat endpoint responded"


def _verify_searxng(host: str, port: int) -> tuple[bool, str]:
    body = _http_get(f"http://{host}:{port}/config")
    if body and ("searx" in body.lower()):
        return True, "/config responded with a SearXNG-shaped payload"
    return False, "port open but /config did not look like SearXNG"


def _verify_spiderfoot(host: str, port: int) -> tuple[bool, str]:
    body = _http_get(f"http://{host}:{port}/")
    if body and "spiderfoot" in body.lower():
        return True, "/ responded with a SpiderFoot-shaped payload"
    return False, "port open but response did not mention SpiderFoot"


def _verify_opensearch(host: str, port: int) -> tuple[bool, str]:
    body = _http_get(f"http://{host}:{port}/")
    if body and "opensearch" in body.lower():
        return True, "/ responded with an OpenSearch-shaped payload"
    return False, "port open but response did not look like OpenSearch"


def _verify_bentopdf(host: str, port: int) -> tuple[bool, str]:
    body = _http_get(f"http://{host}:{port}/")
    if body is not None:
        return True, "/ responded (weakest signal of the six checks — BentoPDF has no distinctive API to confirm against)"
    return False, "port open but no HTTP response"


SERVICES: tuple[ServiceCapability, ...] = (
    ServiceCapability("Ollama", 11434, ("OLLAMA_BASE_URL",), "ollama", _verify_ollama),
    ServiceCapability("ChromaDB", 8000, ("CHROMADB_HOST", "CHROMADB_PORT"), "chromadb", _verify_chromadb),
    ServiceCapability("SearXNG", 8080, ("SEARXNG_INSTANCE",), "searxng", _verify_searxng),
    ServiceCapability("SpiderFoot", 5001, ("SPIDERFOOT_URL",), "spiderfoot", _verify_spiderfoot),
    ServiceCapability("OpenSearch", 9200, ("OPENSEARCH_URL",), "opensearch", _verify_opensearch),
    ServiceCapability("BentoPDF", 3000, ("BENTOPDF_URL",), "bentopdf", _verify_bentopdf),
)


def check_service(capability: ServiceCapability, extra_hosts: tuple[str, ...] = ()) -> ServiceCheck:
    hosts_to_try = ("localhost",) + extra_hosts
    for host in hosts_to_try:
        if not _port_open(host, capability.port):
            continue
        ok, detail = capability.verify(host, capability.port)
        if ok:
            return ServiceCheck(
                capability=capability, found_at=f"{host}:{capability.port}",
                verified=True, detail=detail,
            )
        # Port open but didn't verify — keep trying other hosts before giving up
        # (e.g. localhost has an unrelated service, host.docker.internal has ours).
    return ServiceCheck(capability=capability, verified=False, detail="not found on any checked host")


def scan_services() -> list[ServiceCheck]:
    """Check `localhost` always, plus `host.docker.internal` when this process
    is itself containerized (already routable — see docker-compose.yml's
    `extra_hosts` on the main `odysseus` service)."""
    extra = ("host.docker.internal",) if running_in_container() else ()
    return [check_service(c, extra_hosts=extra) for c in SERVICES]


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_scan() -> ScanResult:
    in_container = running_in_container()
    binaries = [] if in_container else scan_toolchain_binaries()
    services = scan_services()
    return ScanResult(in_container=in_container, binaries=binaries, services=services)


def isolation_tradeoff_warning() -> str:
    return (
        "Note: reusing a host tool/service trades away some of the isolation "
        "a fresh VM or container would otherwise guarantee — the reused "
        "component now behaves however it behaves on this machine, not "
        "however this fork's own pinned image behaves. Fine for convenience; "
        "worth knowing if something acts differently than expected later."
    )


def format_env_suggestion(check) -> str:
    """Render the .env line(s) accepting a reuse suggestion would add."""
    if isinstance(check, BinaryCheck):
        return f"{check.capability.env_var}=local"
    if isinstance(check, ServiceCheck):
        host, port = check.found_at.split(":")
        lines = []
        for var in check.capability.env_vars:
            if var.endswith("_HOST"):
                lines.append(f"{var}={host}")
            elif var.endswith("_PORT"):
                lines.append(f"{var}={port}")
            else:
                lines.append(f"{var}=http://{host}:{port}")
        return "\n".join(lines)
    raise TypeError(f"not a BinaryCheck or ServiceCheck: {check!r}")
