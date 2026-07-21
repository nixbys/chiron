"""Unit tests for mcp_servers/common.py's local/container exec-mode branching."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp_servers import common


def test_resolve_exec_mode_defaults_to_container(monkeypatch):
    monkeypatch.delenv("TOOLCHAIN_EXEC_MODE_NMAP", raising=False)
    monkeypatch.setattr(common, "_EXEC_MODE_DEFAULT", "container")
    assert common._resolve_exec_mode("nmap") == "container"


def test_resolve_exec_mode_global_override(monkeypatch):
    monkeypatch.delenv("TOOLCHAIN_EXEC_MODE_NMAP", raising=False)
    monkeypatch.setattr(common, "_EXEC_MODE_DEFAULT", "local")
    assert common._resolve_exec_mode("nmap") == "local"


def test_resolve_exec_mode_per_tool_overrides_global(monkeypatch):
    monkeypatch.setattr(common, "_EXEC_MODE_DEFAULT", "container")
    monkeypatch.setenv("TOOLCHAIN_EXEC_MODE_NMAP", "local")
    assert common._resolve_exec_mode("nmap") == "local"
    # A different binary is unaffected by nmap's override.
    monkeypatch.delenv("TOOLCHAIN_EXEC_MODE_GOBUSTER", raising=False)
    assert common._resolve_exec_mode("gobuster") == "container"


def test_exec_local_not_installed(monkeypatch):
    monkeypatch.setattr(common.shutil, "which", lambda binary: None)
    output = common._exec_local(["totally-not-a-real-binary"], timeout=5, stdin=None)
    assert "[error:not_installed]" in output


@patch("mcp_servers.common.subprocess.run")
def test_exec_local_returns_stdout(mock_run, monkeypatch):
    monkeypatch.setattr(common.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    mock_run.return_value = MagicMock(stdout="22/tcp open ssh", stderr="", returncode=0)
    output = common._exec_local(["nmap", "-sV", "127.0.0.1"], timeout=5, stdin=None)
    assert "22/tcp" in output
    assert mock_run.called


@patch("mcp_servers.common.subprocess.run")
def test_exec_local_includes_stderr(mock_run, monkeypatch):
    monkeypatch.setattr(common.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    mock_run.return_value = MagicMock(stdout="", stderr="permission denied", returncode=1)
    output = common._exec_local(["nmap"], timeout=5, stdin=None)
    assert "[stderr]" in output
    assert "permission denied" in output


@patch("mcp_servers.common.subprocess.run")
def test_exec_local_timeout(mock_run, monkeypatch):
    monkeypatch.setattr(common.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmap"], timeout=5)
    output = common._exec_local(["nmap"], timeout=5, stdin=None)
    assert "[error:timeout]" in output


@patch("mcp_servers.common._exec_local")
@patch("mcp_servers.common._exec_container")
def test_exec_in_toolchain_dispatches_to_container_by_default(mock_container, mock_local, monkeypatch):
    monkeypatch.setattr(common, "_EXEC_MODE_DEFAULT", "container")
    monkeypatch.delenv("TOOLCHAIN_EXEC_MODE_NMAP", raising=False)
    mock_container.return_value = "container output"
    result = common.exec_in_toolchain(["nmap", "127.0.0.1"])
    assert result == "container output"
    mock_container.assert_called_once()
    mock_local.assert_not_called()


@patch("mcp_servers.common._exec_local")
@patch("mcp_servers.common._exec_container")
def test_exec_in_toolchain_dispatches_to_local_when_selected(mock_container, mock_local, monkeypatch):
    monkeypatch.setattr(common, "_EXEC_MODE_DEFAULT", "container")
    monkeypatch.setenv("TOOLCHAIN_EXEC_MODE_NMAP", "local")
    mock_local.return_value = "local output"
    result = common.exec_in_toolchain(["nmap", "127.0.0.1"])
    assert result == "local output"
    mock_local.assert_called_once()
    mock_container.assert_not_called()
