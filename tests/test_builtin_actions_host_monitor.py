"""Unit tests for src.builtin_actions.action_host_monitor.

Mocks host_telemetry_server's _X_fetch functions (no real psutil calls) and
the MCP manager / monitor_server SQLite drift store, mirroring
tests/test_builtin_actions_scheduled_recon.py's fixture pattern.
"""

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.builtin_actions import TaskNoop, action_host_monitor


class _FakeMcpManager:
    def __init__(self, tools=None, call_results=None):
        self._tools = tools or []
        self._call_results = call_results or {}
        self.calls = []

    def get_all_tools(self):
        return self._tools

    async def call_tool(self, qualified_name, args):
        self.calls.append((qualified_name, args))
        return self._call_results.get(qualified_name, {"stdout": "", "stderr": "", "exit_code": 0})


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


def _processes(names):
    return {"processes": [{"pid": i, "name": n, "user": "root", "cmdline": n} for i, n in enumerate(names)]}


@pytest.mark.asyncio
async def test_invalid_json_prompt():
    result, success = await action_host_monitor("owner1", prompt="not json")
    assert success is False
    assert "JSON" in result


@pytest.mark.asyncio
async def test_unknown_check_type_reports_error_not_crash():
    mgr = _FakeMcpManager(tools=[_FINDINGS_TOOL])
    prompt = json.dumps({"checks": ["bogus"]})
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        result, success = await action_host_monitor("owner1", task_id="task-1", prompt=prompt)
    assert success is False
    assert "unknown check type" in result


@pytest.mark.asyncio
async def test_first_run_establishes_baseline_no_finding():
    import mcp_servers.host_telemetry_server as host_mod
    mgr = _FakeMcpManager(tools=[_FINDINGS_TOOL])
    prompt = json.dumps({"checks": ["processes"]})
    with patch.object(host_mod, "_processes_fetch", return_value=_processes(["sshd"])), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_host_monitor("owner1", task_id="task-1", prompt=prompt)
    assert not any(c[0] == "mcp__findings__finding_index" for c in mgr.calls)


@pytest.mark.asyncio
async def test_second_run_with_drift_files_finding_and_notifies():
    import mcp_servers.host_telemetry_server as host_mod
    prompt = json.dumps({"checks": ["processes"], "engagement_id": "eng-1"})
    mgr = _FakeMcpManager(tools=[_FINDINGS_TOOL])
    with patch.object(host_mod, "_processes_fetch", return_value=_processes(["sshd"])), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_host_monitor("owner1", task_id="task-1", prompt=prompt)

    mgr2 = _FakeMcpManager(tools=[_FINDINGS_TOOL])
    mock_dispatch = AsyncMock(return_value={"browser_sent": True})
    with patch.object(host_mod, "_processes_fetch", return_value=_processes(["sshd", "cryptominer"])), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr2), \
         patch("routes.note_routes.dispatch_reminder", mock_dispatch), \
         patch("src.event_bus.fire_event") as mock_fire_event:
        result, success = await action_host_monitor("owner1", task_id="task-1", prompt=prompt)

    assert success is True
    assert "cryptominer" in result
    finding_calls = [c for c in mgr2.calls if c[0] == "mcp__findings__finding_index"]
    assert len(finding_calls) == 1
    assert finding_calls[0][1]["engagement"] == "eng-1"
    mock_dispatch.assert_awaited_once()
    mock_fire_event.assert_called_once_with("security_finding_added", "owner1")


@pytest.mark.asyncio
async def test_kernel_threads_excluded_from_process_diff():
    """A kernel thread's name/user is stable but psutil's own pid-churn signal
    (empty cmdline) must never surface as drift -- see the fetch-time filter
    in _host_monitor_processes_items."""
    import mcp_servers.host_telemetry_server as host_mod
    mgr = _FakeMcpManager(tools=[_FINDINGS_TOOL])
    kthread_snapshot_1 = {"processes": [
        {"pid": 4, "name": "kworker/0:0", "user": "root", "cmdline": ""},
        {"pid": 1, "name": "sshd", "user": "root", "cmdline": "sshd"},
    ]}
    kthread_snapshot_2 = {"processes": [
        {"pid": 9, "name": "kworker/0:1", "user": "root", "cmdline": ""},  # renumbered
        {"pid": 1, "name": "sshd", "user": "root", "cmdline": "sshd"},
    ]}
    prompt = json.dumps({"checks": ["processes"]})
    with patch.object(host_mod, "_processes_fetch", return_value=kthread_snapshot_1), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_host_monitor("owner1", task_id="task-1", prompt=prompt)

    with patch.object(host_mod, "_processes_fetch", return_value=kthread_snapshot_2), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_host_monitor("owner1", task_id="task-1", prompt=prompt)
