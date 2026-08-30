"""
mcp_servers/common.py

Shared utilities for Chiron MCP servers:
  exec_in_toolchain() — run a command via the Kali sidecar exec API, or
                        locally on this host if TOOLCHAIN_EXEC_MODE(_<BIN>)
                        selects "local". Every call is rate-limited and
                        logged to a shared audit trail -- see
                        _check_rate_limit()/_log_invocation() below and
                        mcp_servers/audit_server.py for the read side.
  mcp_error()         — standardized [error:code] message format
  validate_ip()       — validates IP address, CIDR range, or hostname
  validate_url()      — validates http/https URL
  validate_domain()   — validates domain name / hostname
"""

import ipaddress
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

_TOOLCHAIN_API = os.environ.get("ODYSSEUS_TOOLCHAIN_API", "http://odysseus-toolchain:8088")
_EXEC_TOKEN = os.environ.get("EXEC_API_TOKEN", "")
_EXEC_MODE_DEFAULT = os.environ.get("TOOLCHAIN_EXEC_MODE", "container")
_warned_local_binaries: set[str] = set()

# ── Audit trail + rate limiting ──────────────────────────────────────────
#
# Findings persistence (findings_server.py) already covers *results*; this
# covers *actions* -- what actually ran, against what, when, and how it
# turned out. One shared SQLite file (WAL mode, same pattern every other
# fork-added store already uses) rather than an in-memory counter, for two
# reasons: it survives a server restart, and -- more importantly -- every
# MCP server is its own subprocess, so an in-memory limiter would only ever
# throttle calls from *that one* server. Querying "how many `nmap` calls
# landed here in the last N seconds" against a shared file gives a true
# cross-process limit for free, using the audit log as its own source of
# truth instead of a second counter that could drift from it.
_DATA_DIR = Path(os.environ.get("ODYSSEUS_DATA_DIR", "./data"))
_AUDIT_DB_PATH = _DATA_DIR / "audit.db"
_audit_db_initialized = False

# 0 (or unset) disables rate limiting entirely -- useful for local dev/tests
# and for anyone who's decided the audit log's visibility is enough on its
# own. TOOLCHAIN_RATE_LIMIT_<BINARY> overrides the global limit for one
# binary, same override shape as TOOLCHAIN_EXEC_MODE_<BINARY>.
_RATE_LIMIT_WINDOW_S = int(os.environ.get("TOOLCHAIN_RATE_LIMIT_WINDOW", "60") or 0)
_RATE_LIMIT_DEFAULT = int(os.environ.get("TOOLCHAIN_RATE_LIMIT", "20") or 0)

# Args can carry large payloads (a YARA rule body, a Sigma rule, an nmap
# script arg list) -- cap what's persisted per call so the audit log can't
# become the largest file in the data dir.
_MAX_LOGGED_ARG_LEN = 2000


def _get_audit_db() -> sqlite3.Connection:
    global _audit_db_initialized
    _AUDIT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_AUDIT_DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    if not _audit_db_initialized:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tool_invocations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    binary TEXT NOT NULL,
                    args TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    duration_ms INTEGER,
                    outcome TEXT NOT NULL,
                    detail TEXT DEFAULT ''
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_invocations_binary_ts ON tool_invocations(binary, ts);")
        _audit_db_initialized = True
    return conn


def _log_invocation(binary: str, args: list[str], mode: str, duration_ms: int | None, outcome: str, detail: str = "") -> None:
    """Best-effort audit write -- a logging bug must never break an actual
    scan, so any failure here is swallowed (and reported to the module
    logger, not raised)."""
    try:
        args_json = json.dumps(args)[:_MAX_LOGGED_ARG_LEN]
        conn = _get_audit_db()
        try:
            conn.execute(
                "INSERT INTO tool_invocations (ts, binary, args, mode, duration_ms, outcome, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), binary, args_json, mode, duration_ms, outcome, detail[:500]),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        logger.warning("Failed to write audit log entry for %r", binary, exc_info=True)


def _rate_limit_for(binary: str) -> int:
    """Resolve the per-window invocation limit for one binary: a
    TOOLCHAIN_RATE_LIMIT_<BINARY> override wins, falling back to the global
    TOOLCHAIN_RATE_LIMIT (default 20/window). 0 disables the check."""
    per_tool = os.environ.get(f"TOOLCHAIN_RATE_LIMIT_{binary.upper()}")
    if per_tool is not None and per_tool != "":
        try:
            return int(per_tool)
        except ValueError:
            pass
    return _RATE_LIMIT_DEFAULT


def _check_rate_limit(binary: str) -> str | None:
    """Return None if under the limit, or an mcp_error string if not.
    Best-effort: a query failure here fails OPEN (never blocks a real scan
    over an audit-log hiccup) rather than closed."""
    if _RATE_LIMIT_WINDOW_S <= 0:
        return None
    limit = _rate_limit_for(binary)
    if limit <= 0:
        return None
    try:
        conn = _get_audit_db()
        try:
            since = time.time() - _RATE_LIMIT_WINDOW_S
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM tool_invocations WHERE binary=? AND ts>? AND outcome!='rate_limited'",
                (binary, since),
            ).fetchone()
            count = row["n"] if row else 0
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        logger.warning("Rate-limit check failed for %r -- failing open", binary, exc_info=True)
        return None
    if count >= limit:
        return mcp_error(
            "rate_limited",
            f"{binary!r} has run {count} times in the last {_RATE_LIMIT_WINDOW_S}s "
            f"(limit {limit}) — wait before retrying, or raise TOOLCHAIN_RATE_LIMIT"
            f"_{binary.upper()}/TOOLCHAIN_RATE_LIMIT.",
        )
    return None


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
    (globally or per-binary via TOOLCHAIN_EXEC_MODE_<BINARY>) selects "local".

    Every call is rate-limited (TOOLCHAIN_RATE_LIMIT / TOOLCHAIN_RATE_LIMIT_
    <BINARY>, see _check_rate_limit) and logged to the shared audit trail
    (mcp_servers/audit_server.py reads it back) -- this is the one chokepoint
    every red-team MCP server's tool calls pass through, so it's the one
    place to add both without touching 15+ individual server modules."""
    if not cmd:
        return mcp_error("invalid_command", "No command given")
    binary = cmd[0]

    if err := _check_rate_limit(binary):
        _log_invocation(binary, cmd, "n/a", None, "rate_limited")
        return err

    mode = _resolve_exec_mode(binary)
    started = time.monotonic()
    result = _exec_local(cmd, timeout, stdin) if mode == "local" else _exec_container(cmd, timeout, stdin)
    duration_ms = int((time.monotonic() - started) * 1000)

    if result.startswith("[error:timeout]"):
        outcome, detail = "timeout", result
    elif result.startswith("[error:"):
        outcome, detail = "error", result
    else:
        outcome, detail = "ok", ""
    _log_invocation(binary, cmd, mode, duration_ms, outcome, detail)

    return result


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
