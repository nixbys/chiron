"""Unit tests for src.builtin_actions.action_yara_sweep.

Mocks the MCP manager (no real subprocess servers / toolchain container) and
monitor_server's SQLite drift store (temp dir, matching
tests/test_builtin_actions_scheduled_recon.py's fixture pattern).
"""

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.builtin_actions import TaskNoop, action_yara_sweep


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


_YARA_TOOL = {"name": "yara_scan", "qualified_name": "mcp__yara__yara_scan", "is_disabled": False}
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
    result, success = await action_yara_sweep("owner1", prompt="{}")
    assert success is False
    assert "no target" in result


@pytest.mark.asyncio
async def test_invalid_json_prompt():
    result, success = await action_yara_sweep("owner1", prompt="not json")
    assert success is False
    assert "JSON" in result


@pytest.mark.asyncio
async def test_first_run_establishes_baseline_no_finding():
    mgr = _FakeMcpManager(
        tools=[_YARA_TOOL, _FINDINGS_TOOL],
        call_results={"mcp__yara__yara_scan": {"stdout": "EICAR_Test /workspaces/case-1/evidence/a.txt", "exit_code": 0}},
    )
    prompt = json.dumps({"target": "case-1/evidence"})
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_yara_sweep("owner1", task_id="task-1", prompt=prompt)
    assert not any(c[0] == "mcp__findings__finding_index" for c in mgr.calls)


@pytest.mark.asyncio
async def test_second_run_with_drift_files_finding_and_notifies():
    prompt = json.dumps({"target": "case-1/evidence", "engagement_id": "eng-1"})
    mgr = _FakeMcpManager(
        tools=[_YARA_TOOL, _FINDINGS_TOOL],
        call_results={"mcp__yara__yara_scan": {"stdout": "EICAR_Test /workspaces/case-1/evidence/a.txt", "exit_code": 0}},
    )
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_yara_sweep("owner1", task_id="task-1", prompt=prompt)

    mgr2 = _FakeMcpManager(
        tools=[_YARA_TOOL, _FINDINGS_TOOL],
        call_results={"mcp__yara__yara_scan": {
            "stdout": "EICAR_Test /workspaces/case-1/evidence/a.txt\nSuspicious_Macro /workspaces/case-1/evidence/b.docm",
            "exit_code": 0,
        }},
    )
    mock_dispatch = AsyncMock(return_value={"browser_sent": True})
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr2), \
         patch("routes.note_routes.dispatch_reminder", mock_dispatch), \
         patch("src.event_bus.fire_event") as mock_fire_event:
        result, success = await action_yara_sweep("owner1", task_id="task-1", prompt=prompt)

    assert success is True
    assert "Suspicious_Macro" in result
    finding_calls = [c for c in mgr2.calls if c[0] == "mcp__findings__finding_index"]
    assert len(finding_calls) == 1
    assert finding_calls[0][1]["engagement"] == "eng-1"
    mock_dispatch.assert_awaited_once()
    mock_fire_event.assert_called_once_with("security_finding_added", "owner1")


@pytest.mark.asyncio
async def test_unregistered_tool_reports_error_not_crash():
    mgr = _FakeMcpManager(tools=[])  # yara_scan not registered
    prompt = json.dumps({"target": "case-1/evidence"})
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        result, success = await action_yara_sweep("owner1", task_id="task-1", prompt=prompt)
    assert success is False
    assert "not registered" in result or "isn't registered" in result


@pytest.mark.asyncio
async def test_scan_error_reports_error_not_crash():
    mgr = _FakeMcpManager(
        tools=[_YARA_TOOL, _FINDINGS_TOOL],
        call_results={"mcp__yara__yara_scan": {"stdout": "[error:invalid_path] Target must be a relative path under /workspaces/", "exit_code": 0}},
    )
    prompt = json.dumps({"target": "../etc"})
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        result, success = await action_yara_sweep("owner1", task_id="task-1", prompt=prompt)
    assert success is False
    assert "failed" in result
