"""Unit tests for src.builtin_actions.action_watchlist_check.

Mocks intel_server's raw provider-fetch functions and watchlist_server's
SQLite store (temp dir), plus reminder/event dispatch.
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.builtin_actions import TaskNoop, action_watchlist_check


@pytest.fixture(autouse=True)
def tmp_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    import importlib
    import mcp_servers.watchlist_server as watchlist_mod
    importlib.reload(watchlist_mod)
    yield watchlist_mod


@pytest.fixture
def with_shodan_key(monkeypatch):
    import mcp_servers.intel_server as intel_mod
    monkeypatch.setattr(intel_mod, "_SHODAN_KEY", "test-key")
    monkeypatch.setattr(intel_mod, "_VT_KEY", "")
    monkeypatch.setattr(intel_mod, "_OTX_KEY", "")
    monkeypatch.setattr(intel_mod, "_CENSYS_ID", "")
    monkeypatch.setattr(intel_mod, "_CENSYS_SECRET", "")
    yield


@pytest.mark.asyncio
async def test_empty_watchlist_raises_noop(tmp_data_dir):
    with pytest.raises(TaskNoop, match="empty"):
        await action_watchlist_check("owner1")


@pytest.mark.asyncio
async def test_no_api_keys_raises_noop(tmp_data_dir, monkeypatch):
    import mcp_servers.intel_server as intel_mod
    monkeypatch.setattr(intel_mod, "_SHODAN_KEY", "")
    monkeypatch.setattr(intel_mod, "_VT_KEY", "")
    monkeypatch.setattr(intel_mod, "_OTX_KEY", "")
    monkeypatch.setattr(intel_mod, "_CENSYS_ID", "")
    monkeypatch.setattr(intel_mod, "_CENSYS_SECRET", "")

    mod = tmp_data_dir
    await mod.call_tool("watchlist_add", {"indicator": "203.0.113.1", "kind": "ip"})

    with pytest.raises(TaskNoop, match="no threat-intel API keys"):
        await action_watchlist_check("owner1")


@pytest.mark.asyncio
async def test_baseline_check_does_not_fire_finding(tmp_data_dir, with_shodan_key):
    mod = tmp_data_dir
    await mod.call_tool("watchlist_add", {"indicator": "203.0.113.1", "kind": "ip"})

    with patch("mcp_servers.intel_server._shodan_fetch", return_value={"ports": [22, 80], "vulns": {}}):
        with pytest.raises(TaskNoop, match="no changes detected"):
            await action_watchlist_check("owner1")


@pytest.mark.asyncio
async def test_second_check_with_change_files_finding_and_notifies(tmp_data_dir, with_shodan_key):
    mod = tmp_data_dir
    await mod.call_tool("watchlist_add", {"indicator": "203.0.113.1", "kind": "ip", "engagement_id": "eng-1"})

    class _FakeMcpManager:
        def __init__(self):
            self.calls = []

        async def call_tool(self, qualified_name, args):
            self.calls.append((qualified_name, args))
            return {"stdout": "ok", "exit_code": 0}

    mgr = _FakeMcpManager()
    finding_tool = {"name": "finding_index", "qualified_name": "mcp__findings__finding_index", "is_disabled": False}
    mgr.get_all_tools = lambda: [finding_tool]

    with patch("mcp_servers.intel_server._shodan_fetch", return_value={"ports": [22, 80], "vulns": {}}):
        with pytest.raises(TaskNoop):
            await action_watchlist_check("owner1")

    mock_dispatch = AsyncMock(return_value={"browser_sent": True})
    with patch("mcp_servers.intel_server._shodan_fetch", return_value={"ports": [22, 80, 443], "vulns": {"CVE-2024-0001": {}}}), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr), \
         patch("routes.note_routes.dispatch_reminder", mock_dispatch), \
         patch("src.event_bus.fire_event") as mock_fire_event:
        summary, success = await action_watchlist_check("owner1")

    assert success is True
    assert "203.0.113.1" in summary
    finding_calls = [c for c in mgr.calls if c[0] == "mcp__findings__finding_index"]
    assert len(finding_calls) == 1
    assert finding_calls[0][1]["engagement"] == "eng-1"
    mock_dispatch.assert_awaited_once()
    mock_fire_event.assert_called_once_with("security_finding_added", "owner1")


@pytest.mark.asyncio
async def test_provider_error_is_skipped_not_fatal(tmp_data_dir, with_shodan_key):
    mod = tmp_data_dir
    await mod.call_tool("watchlist_add", {"indicator": "203.0.113.1", "kind": "ip"})

    with patch("mcp_servers.intel_server._shodan_fetch", return_value={"_mcp_error": "rate limited"}):
        with pytest.raises(TaskNoop, match="no changes detected"):
            await action_watchlist_check("owner1")
