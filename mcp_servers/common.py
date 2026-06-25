"""
mcp_servers/common.py

Shared utilities for odysseus-red MCP servers:
  exec_in_toolchain() — call the Kali sidecar exec API
  mcp_error()         — standardized [error:code] message format
  validate_ip()       — validates IP address, CIDR range, or hostname
  validate_url()      — validates http/https URL
  validate_domain()   — validates domain name / hostname
"""

import ipaddress
import os
import re
from urllib.parse import urlparse

import requests

_TOOLCHAIN_API = os.environ.get("ODYSSEUS_TOOLCHAIN_API", "http://odysseus-toolchain:8088")
_EXEC_TOKEN = os.environ.get("EXEC_API_TOKEN", "")


def exec_in_toolchain(
    cmd: list[str],
    timeout: int = 300,
    stdin: str | None = None,
) -> str:
    """Execute a command in the Kali sidecar and return combined stdout+stderr."""
    headers = {"Authorization": f"Bearer {_EXEC_TOKEN}"} if _EXEC_TOKEN else {}
    try:
        resp = requests.post(
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
