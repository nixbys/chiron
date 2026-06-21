"""Unit tests for recon_server.py — mock out subprocess so no real container needed."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp_servers.recon_server import _exec_in_toolchain, call_tool


def _make_completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    result = MagicMock(spec=subprocess.CompletedProcess)
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


@patch("mcp_servers.recon_server.subprocess.run")
def test_nmap_scan_returns_output(mock_run):
    mock_run.return_value = _make_completed(stdout="Nmap scan report for 127.0.0.1\nPORT 22/tcp open ssh")
    output = _exec_in_toolchain(["nmap", "-sV", "127.0.0.1"])
    assert "22/tcp" in output
    assert mock_run.called


@patch("mcp_servers.recon_server.subprocess.run")
def test_timeout_returns_message(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmap"], timeout=5)
    output = _exec_in_toolchain(["nmap", "127.0.0.1"], timeout=5)
    assert "timeout" in output.lower()


@patch("mcp_servers.recon_server.subprocess.run")
def test_missing_runtime_returns_error(mock_run):
    mock_run.side_effect = FileNotFoundError()
    output = _exec_in_toolchain(["nmap", "127.0.0.1"])
    assert "error" in output.lower()


@pytest.mark.asyncio
@patch("mcp_servers.recon_server.subprocess.run")
async def test_call_tool_nmap(mock_run):
    mock_run.return_value = _make_completed(stdout="80/tcp open http")
    results = await call_tool("nmap_scan", {"target": "192.0.2.1"})
    assert results
    assert "80/tcp" in results[0].text


@pytest.mark.asyncio
async def test_call_tool_unknown():
    results = await call_tool("nonexistent_tool", {})
    assert "Unknown tool" in results[0].text
