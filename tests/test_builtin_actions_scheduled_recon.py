"""Unit tests for src.builtin_actions.action_scheduled_recon.

Mocks the MCP manager (no real subprocess servers), monitor_server's SQLite
store (temp dir, matching mcp_servers test fixtures), and the reminder/event
dispatch calls.
"""

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.builtin_actions import TaskNoop, action_scheduled_recon


class _FakeMcpManager:
    def __init__(self, tools, call_results=None):
        self._tools = tools
        self._call_results = call_results or {}
        self.calls = []

    def get_all_tools(self):
        return self._tools

    async def call_tool(self, qualified_name, args):
        self.calls.append((qualified_name, args))
        return self._call_results.get(qualified_name, {"stdout": "", "stderr": "", "exit_code": 0})


_NMAP_TOOL = {"name": "nmap_scan", "qualified_name": "mcp__recon__nmap_scan", "is_disabled": False}
_FINDINGS_TOOL = {"name": "finding_index", "qualified_name": "mcp__findings__finding_index", "is_disabled": False}


@pytest.fixture(autouse=True)
def tmp_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    import importlib
    import mcp_servers.engagement_server as engagement_mod
    import mcp_servers.monitor_server as monitor_mod
    importlib.reload(monitor_mod)
    importlib.reload(engagement_mod)
    yield


@pytest.mark.asyncio
async def test_no_target_configured():
    result, success = await action_scheduled_recon("owner1", prompt=json.dumps({"checks": ["ports"]}))
    assert success is False
    assert "no target" in result


@pytest.mark.asyncio
async def test_invalid_json_prompt():
    result, success = await action_scheduled_recon("owner1", prompt="not json")
    assert success is False
    assert "JSON" in result


@pytest.mark.asyncio
async def test_first_run_establishes_baseline_no_finding():
    mgr = _FakeMcpManager(
        tools=[_NMAP_TOOL, _FINDINGS_TOOL],
        call_results={"mcp__recon__nmap_scan": {"stdout": "22/tcp open ssh\n80/tcp open http", "exit_code": 0}},
    )
    prompt = json.dumps({"target": "192.0.2.1", "checks": ["ports"]})
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_scheduled_recon("owner1", task_id="task-1", prompt=prompt)
    # No finding_index call on the baseline run.
    assert not any(c[0] == "mcp__findings__finding_index" for c in mgr.calls)


@pytest.mark.asyncio
async def test_second_run_with_drift_files_finding_and_notifies():
    prompt = json.dumps({"target": "192.0.2.1", "checks": ["ports"], "engagement_id": "eng-1"})
    mgr = _FakeMcpManager(
        tools=[_NMAP_TOOL, _FINDINGS_TOOL],
        call_results={"mcp__recon__nmap_scan": {"stdout": "22/tcp open ssh", "exit_code": 0}},
    )
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_scheduled_recon("owner1", task_id="task-1", prompt=prompt)

    # Second run: a new port shows up.
    mgr2 = _FakeMcpManager(
        tools=[_NMAP_TOOL, _FINDINGS_TOOL],
        call_results={"mcp__recon__nmap_scan": {"stdout": "22/tcp open ssh\n443/tcp open https", "exit_code": 0}},
    )
    mock_dispatch = AsyncMock(return_value={"browser_sent": True})
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr2), \
         patch("routes.note_routes.dispatch_reminder", mock_dispatch), \
         patch("src.event_bus.fire_event") as mock_fire_event:
        result, success = await action_scheduled_recon("owner1", task_id="task-1", prompt=prompt)

    assert success is True
    assert "443/tcp" in result
    finding_calls = [c for c in mgr2.calls if c[0] == "mcp__findings__finding_index"]
    assert len(finding_calls) == 1
    assert finding_calls[0][1]["engagement"] == "eng-1"
    mock_dispatch.assert_awaited_once()
    mock_fire_event.assert_called_once_with("security_finding_added", "owner1")


@pytest.mark.asyncio
async def test_unregistered_tool_reports_error_not_crash():
    mgr = _FakeMcpManager(tools=[])  # nmap_scan not registered
    prompt = json.dumps({"target": "192.0.2.1", "checks": ["ports"]})
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        result, success = await action_scheduled_recon("owner1", task_id="task-1", prompt=prompt)
    assert success is False
    assert "not registered" in result or "isn't registered" in result


@pytest.mark.asyncio
async def test_cve_check_uses_shodan_fetch_directly():
    prompt = json.dumps({"target": "192.0.2.1", "checks": ["cve"]})
    mgr = _FakeMcpManager(tools=[_FINDINGS_TOOL])
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr), \
         patch("mcp_servers.intel_server._shodan_fetch", return_value={"vulns": {"CVE-2024-0001": {}}}):
        with pytest.raises(TaskNoop):
            await action_scheduled_recon("owner1", task_id="task-1", prompt=prompt)

    with patch("src.tool_utils.get_mcp_manager", return_value=mgr), \
         patch("mcp_servers.intel_server._shodan_fetch", return_value={"vulns": {"CVE-2024-0001": {}, "CVE-2024-0002": {}}}), \
         patch("routes.note_routes.dispatch_reminder", AsyncMock(return_value={})), \
         patch("src.event_bus.fire_event"):
        result, success = await action_scheduled_recon("owner1", task_id="task-1", prompt=prompt)
    assert success is True
    assert "CVE-2024-0002" in result
