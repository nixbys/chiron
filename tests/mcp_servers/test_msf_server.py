"""Unit tests for msf_server.py — mock the exec API HTTP call so no real
container/Metasploit install is needed. Read-only search/info only --
see the module docstring for why exploit execution isn't in scope here."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp_servers.msf_server import call_tool


def _make_response(stdout: str = "", stderr: str = "", returncode: int = 0, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {"stdout": stdout, "stderr": stderr, "returncode": returncode}
    resp.raise_for_status = MagicMock()
    return resp


@pytest.mark.asyncio
@patch("mcp_servers.common.requests.post")
async def test_msf_search_returns_module_list(mock_post):
    mock_post.return_value = _make_response(
        stdout="Matching Modules\n================\n\n   #  Name                                   Disclosure Date\n   -  ----                                   ---------------\n   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14"
    )
    results = await call_tool("msf_search", {"query": "eternalblue"})
    assert results
    assert "ms17_010_eternalblue" in results[0].text


@pytest.mark.asyncio
@patch("mcp_servers.common.requests.post")
async def test_msf_search_command_is_built_correctly(mock_post):
    mock_post.return_value = _make_response(stdout="ok")
    await call_tool("msf_search", {"query": "type:exploit smb"})
    sent = mock_post.call_args.kwargs["json"]
    assert sent["args"][:3] == ["msfconsole", "-q", "-x"]
    assert sent["args"][3] == "search type:exploit smb; exit"


@pytest.mark.asyncio
async def test_msf_search_empty_query_rejected():
    results = await call_tool("msf_search", {"query": "   "})
    assert "[error:invalid_query]" in results[0].text


@pytest.mark.asyncio
async def test_msf_search_semicolon_injection_rejected():
    # Without this check, msfconsole's own REPL would split this into two
    # commands and actually load+run a module through a "read-only search".
    results = await call_tool("msf_search", {"query": "smb; use exploit/multi/handler; exploit"})
    assert "[error:invalid_query]" in results[0].text


@pytest.mark.asyncio
async def test_msf_search_newline_injection_rejected():
    results = await call_tool("msf_search", {"query": "smb\nuse exploit/multi/handler\nexploit"})
    assert "[error:invalid_query]" in results[0].text


@pytest.mark.asyncio
@patch("mcp_servers.common.requests.post")
async def test_msf_module_info_returns_details(mock_post):
    mock_post.return_value = _make_response(stdout="Name: MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption")
    results = await call_tool("msf_module_info", {"module": "exploit/windows/smb/ms17_010_eternalblue"})
    assert results
    assert "EternalBlue" in results[0].text


@pytest.mark.asyncio
@patch("mcp_servers.common.requests.post")
async def test_msf_module_info_command_is_built_correctly(mock_post):
    mock_post.return_value = _make_response(stdout="ok")
    await call_tool("msf_module_info", {"module": "exploit/windows/smb/ms17_010_eternalblue"})
    sent = mock_post.call_args.kwargs["json"]
    assert sent["args"] == [
        "msfconsole", "-q", "-x", "info exploit/windows/smb/ms17_010_eternalblue; exit",
    ]


@pytest.mark.asyncio
async def test_msf_module_info_rejects_invalid_module_path():
    results = await call_tool("msf_module_info", {"module": "exploit/foo; use exploit/multi/handler"})
    assert "[error:invalid_module]" in results[0].text


@pytest.mark.asyncio
async def test_msf_module_info_rejects_path_with_spaces():
    results = await call_tool("msf_module_info", {"module": "not a real module"})
    assert "[error:invalid_module]" in results[0].text


@pytest.mark.asyncio
async def test_call_tool_unknown():
    results = await call_tool("nonexistent_tool", {})
    assert results
    assert "[error:unknown_tool]" in results[0].text


def test_tools_are_read_only_search_and_info_only():
    """Pin the deliberate scope of this phase: no run/exploit/session tools."""
    from mcp_servers.msf_server import TOOLS
    names = {t.name for t in TOOLS}
    assert names == {"msf_search", "msf_module_info"}
