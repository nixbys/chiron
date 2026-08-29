"""
mcp_servers/common.py

Shared utilities for Chiron MCP servers:
  exec_in_toolchain() — run a command via the Kali sidecar exec API, or
                        locally on this host if TOOLCHAIN_EXEC_MODE(_<BIN>)
                        selects "local"
  mcp_error()         — standardized [error:code] message format
  validate_ip()       — validates IP address, CIDR range, or hostname
  validate_url()      — validates http/https URL
  validate_domain()   — validates domain name / hostname
"""

import ipaddress
import logging
import os
import re
import shutil
import subprocess
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

_TOOLCHAIN_API = os.environ.get("ODYSSEUS_TOOLCHAIN_API", "http://odysseus-toolchain:8088")
_EXEC_TOKEN = os.environ.get("EXEC_API_TOKEN", "")
_EXEC_MODE_DEFAULT = os.environ.get("TOOLCHAIN_EXEC_MODE", "container")
_warned_local_binaries: set[str] = set()


def _resolve_exec_mode(binary: str) -> str:
    """Resolve "local" or "container" for a binary: per-tool env var wins,
    falling back to the global TOOLCHAIN_EXEC_MODE (default: container)."""
    per_tool = os.environ.get(f"TOOLCHAIN_EXEC_MODE_{binary.upper()}")
    mode = (per_tool or _EXEC_MODE_DEFAULT or "container").strip().lower()
    return "local" if mode == "local" else "container"


def _exec_local(cmd: list[str], timeout: int, stdin: str | None) -> str:
    """Execute a command directly on this host and return combined stdout+stderr."""
    binary = cmd[0] if cmd else ""
    if not shutil.which(binary):
        return mcp_error(
            "not_installed",
            f"{binary!r} not found on PATH — install it locally or unset "
            f"TOOLCHAIN_EXEC_MODE_{binary.upper()} to use the toolchain container",
        )
    if binary not in _warned_local_binaries:
        _warned_local_binaries.add(binary)
        logger.warning(
            "TOOLCHAIN_EXEC_MODE=local for %r: running unsandboxed on this host, "
            "outside the toolchain sidecar's capability restrictions",
            binary,
        )
    try:
        result = subprocess.run(  # nosec B603 — args are built by the calling MCP tool, not raw user input
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin,
            check=False,
        )
        out = result.stdout + (f"\n[stderr]\n{result.stderr}" if result.stderr else "")
        return out.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return mcp_error("timeout", f"Command exceeded {timeout}s")
    except Exception as exc:  # noqa: BLE001
        return mcp_error("exec", str(exc))


def _exec_container(cmd: list[str], timeout: int, stdin: str | None) -> str:
    """Execute a command in the Kali sidecar and return combined stdout+stderr."""
    headers = {"Authorization": f"Bearer {_EXEC_TOKEN}"} if _EXEC_TOKEN else {}
    try:
        resp = requests.post(  # nosec B113 — timeout is passed as kwarg on the next line
            f"{_TOOLCHAIN_API}/exec",
            json={"args": cmd, "timeout": timeout, "stdin": stdin},
            headers=headers,
            timeout=timeout + 5,
        )
        resp.raise_for_status()
        data = resp.json()
        stdout = data.get("stdout") or ""
        stderr = data.get("stderr") or ""
        out = stdout + (f"\n[stderr]\n{stderr}" if stderr else "")
        return out.strip() or "(no output)"
    except requests.exceptions.Timeout:
        return mcp_error("timeout", f"Command exceeded {timeout}s")
    except Exception as exc:  # noqa: BLE001
        return mcp_error("network", str(exc))


def exec_in_toolchain(
    cmd: list[str],
    timeout: int = 300,
    stdin: str | None = None,
) -> str:
    """Execute a command in the Kali sidecar, or locally if TOOLCHAIN_EXEC_MODE
    (globally or per-binary via TOOLCHAIN_EXEC_MODE_<BINARY>) selects "local"."""
    if cmd and _resolve_exec_mode(cmd[0]) == "local":
        return _exec_local(cmd, timeout, stdin)
    return _exec_container(cmd, timeout, stdin)


def mcp_error(code: str, message: str) -> str:
    """Return a standardized MCP tool error string."""
    return f"[error:{code}] {message}"


def validate_ip(value: str) -> str | None:
    """Return None if value is a valid IP/CIDR/hostname, or an mcp_error string."""
    try:
        ipaddress.ip_network(value, strict=False)
        return None
    except ValueError:
        pass
    if _is_valid_hostname(value):
        return None
    return mcp_error("invalid_target", f"{value!r} is not a valid IP, CIDR range, or hostname")


def validate_url(url: str) -> str | None:
    """Return None if url is a valid http/https URL, or an mcp_error string."""
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return mcp_error("invalid_url", f"URL scheme must be http or https (got {p.scheme!r})")
        if not p.netloc:
            return mcp_error("invalid_url", "URL must include a hostname")
        return None
    except Exception:  # noqa: BLE001
        return mcp_error("invalid_url", f"Could not parse URL: {url!r}")


def validate_domain(domain: str) -> str | None:
    """Return None if domain is a valid hostname/domain, or an mcp_error string."""
    if not _is_valid_hostname(domain):
        return mcp_error("invalid_domain", f"{domain!r} is not a valid domain name")
    return None


def _is_valid_hostname(h: str) -> bool:
    if not h or len(h) > 253:
        return False
    h = h.rstrip(".")
    return bool(
        re.match(
            r"^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)*"
            r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$",
            h,
        )
    )
