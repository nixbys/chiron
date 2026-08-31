"""Unit tests for recon_server.py — mock the exec API HTTP call so no real container is needed."""

import importlib
import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp_servers import common
from mcp_servers.common import exec_in_toolchain
from mcp_servers.recon_server import call_tool


def _make_response(stdout: str = "", stderr: str = "", returncode: int = 0, status_code: int = 200):
    """Return a mock requests.Response that mimics the exec API JSON payload."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {"stdout": stdout, "stderr": stderr, "returncode": returncode}
    resp.raise_for_status = MagicMock()
    return resp


@patch("mcp_servers.common.requests.post")
def test_exec_in_toolchain_returns_stdout(mock_post):
    mock_post.return_value = _make_response(stdout="Nmap scan report for 127.0.0.1\n22/tcp open ssh")
    output = exec_in_toolchain(["nmap", "-sV", "127.0.0.1"])
    assert "22/tcp" in output
    assert mock_post.called


@patch("mcp_servers.common.requests.post")
def test_exec_in_toolchain_timeout(mock_post):
    mock_post.side_effect = requests.exceptions.Timeout()
    output = exec_in_toolchain(["nmap", "127.0.0.1"], timeout=5)
    assert "[error:timeout]" in output


@patch("mcp_servers.common.requests.post")
def test_exec_in_toolchain_connection_error(mock_post):
    mock_post.side_effect = requests.exceptions.ConnectionError("refused")
    output = exec_in_toolchain(["nmap", "127.0.0.1"])
    assert "[error:network]" in output


@pytest.mark.asyncio
@patch("mcp_servers.common.requests.post")
async def test_call_tool_nmap(mock_post):
    mock_post.return_value = _make_response(stdout="80/tcp open http")
    results = await call_tool("nmap_scan", {"target": "192.0.2.1"})
    assert results
    assert "80/tcp" in results[0].text


@pytest.mark.asyncio
async def test_call_tool_nmap_invalid_target():
    results = await call_tool("nmap_scan", {"target": "not_a_valid_host!@#"})
    assert results
    assert "[error:" in results[0].text


@pytest.mark.asyncio
@patch("mcp_servers.common.requests.post")
async def test_call_tool_masscan(mock_post):
    mock_post.return_value = _make_response(stdout="Discovered open port 443/tcp on 192.0.2.1")
    results = await call_tool("masscan_scan", {"target": "192.0.2.1", "ports": "443"})
    assert results
    assert "443" in results[0].text


@pytest.mark.asyncio
async def test_call_tool_unknown():
    results = await call_tool("nonexistent_tool", {})
    assert results
    assert "[error:unknown_tool]" in results[0].text


@pytest.mark.asyncio
@patch("mcp_servers.common.requests.post")
async def test_call_tool_tls_cert_info(mock_post):
    mock_post.return_value = _make_response(stdout="Not valid before: 2026-01-01\nNot valid after: 2027-01-01")
    results = await call_tool("tls_cert_info", {"host": "192.0.2.1", "port": 443})
    assert results
    assert "Not valid after" in results[0].text


@pytest.mark.asyncio
async def test_call_tool_tls_cert_info_invalid_host():
    results = await call_tool("tls_cert_info", {"host": "not_a_valid_host!@#"})
    assert results
    assert "[error:" in results[0].text


# ---- Engagement scope enforcement (Phase A) ---------------------------------
#
# recon_server is the one representative wired-server test per the plan --
# every other scope-enforced server (web_vuln, osint, intel, watchlist)
# follows the exact same one-line check_scope_from_args() call, so this
# covers the wiring pattern itself rather than repeating it five times.


@pytest.fixture
def scope_env(tmp_path, monkeypatch):
    """Isolated ODYSSEUS_DATA_DIR + a reload of common.py, same pattern as
    test_common.py's audit_env fixture -- recon_server calls
    common.check_scope_from_args by reference, so reloading common alone is
    enough for it to pick up the fresh engagements.db path."""
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("TOOLCHAIN_RATE_LIMIT_WINDOW", "0")  # disable rate limiting for these tests
    importlib.reload(common)
    conn = sqlite3.connect(str(tmp_path / "engagements.db"))
    conn.execute(
        "CREATE TABLE engagements (id TEXT PRIMARY KEY, scope TEXT, out_of_scope TEXT, "
        "authorized_hours TEXT DEFAULT '', blackout_dates TEXT DEFAULT '[]')"
    )
    conn.execute(
        "INSERT INTO engagements (id, scope, out_of_scope) VALUES (?, ?, ?)",
        ("eng-1", json.dumps(["10.0.0.0/24"]), json.dumps([])),
    )
    conn.commit()
    conn.close()
    yield


@pytest.mark.asyncio
@patch("mcp_servers.common.requests.post")
async def test_call_tool_nmap_in_scope_target_proceeds(mock_post, scope_env):
    mock_post.return_value = _make_response(stdout="22/tcp open ssh")
    results = await call_tool("nmap_scan", {"target": "10.0.0.5", "engagement_id": "eng-1"})
    assert "22/tcp" in results[0].text


@pytest.mark.asyncio
async def test_call_tool_nmap_out_of_scope_target_blocks(scope_env):
    results = await call_tool("nmap_scan", {"target": "8.8.8.8", "engagement_id": "eng-1"})
    assert "[error:out_of_scope]" in results[0].text


@pytest.mark.asyncio
@patch("mcp_servers.common.requests.post")
async def test_call_tool_nmap_override_proceeds_and_is_flagged(mock_post, scope_env):
    mock_post.return_value = _make_response(stdout="22/tcp open ssh")
    results = await call_tool(
        "nmap_scan",
        {"target": "8.8.8.8", "engagement_id": "eng-1", "override_scope": True, "override_reason": "approved"},
    )
    assert "22/tcp" in results[0].text
    conn = common._get_audit_db()
    row = conn.execute("SELECT * FROM tool_invocations WHERE outcome='scope_override'").fetchone()
    conn.close()
    assert row is not None
    assert row["engagement_id"] == "eng-1"


@pytest.mark.asyncio
@patch("mcp_servers.common.requests.post")
async def test_call_tool_nmap_no_engagement_id_is_unenforced(mock_post, scope_env):
    """A session/call with no engagement_id is unaffected -- back-compat
    with every existing unscoped call site."""
    mock_post.return_value = _make_response(stdout="22/tcp open ssh")
    results = await call_tool("nmap_scan", {"target": "8.8.8.8"})
    assert "22/tcp" in results[0].text
