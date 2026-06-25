"""Unit tests for recon_server.py — mock the exec API HTTP call so no real container is needed."""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

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
