"""Unit tests for src.builtin_actions.action_sigma_sweep.

Mocks the MCP manager (no real subprocess servers), sigma_server's
_convert_rule/_os_search (no real OpenSearch/pysigma dependency), and
monitor_server's SQLite drift store (temp dir, matching
tests/test_builtin_actions_scheduled_recon.py's fixture pattern).
"""

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.builtin_actions import TaskNoop, action_sigma_sweep


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


_FINDINGS_TOOL = {"name": "finding_index", "qualified_name": "mcp__findings__finding_index", "is_disabled": False}


@pytest.fixture(autouse=True)
def tmp_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    import importlib
    import mcp_servers.engagement_server as engagement_mod
    import mcp_servers.monitor_server as monitor_mod
    import mcp_servers.sigma_server as sigma_mod
    importlib.reload(monitor_mod)
    importlib.reload(engagement_mod)
    importlib.reload(sigma_mod)
    yield


def _hit(doc_id):
    return {"_id": doc_id}


def _search_result(*doc_ids):
    return {"hits": {"hits": [_hit(d) for d in doc_ids]}}


@pytest.mark.asyncio
async def test_invalid_json_prompt():
    result, success = await action_sigma_sweep("owner1", prompt="not json")
    assert success is False
    assert "JSON" in result


@pytest.mark.asyncio
async def test_pysigma_not_installed():
    import mcp_servers.sigma_server as sigma_mod
    mgr = _FakeMcpManager(tools=[_FINDINGS_TOOL])
    with patch.object(sigma_mod, "_PYSIGMA_AVAILABLE", False), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        result, success = await action_sigma_sweep("owner1", task_id="task-1", prompt="{}")
    assert success is False
    assert "not installed" in result


@pytest.mark.asyncio
async def test_no_stored_rules_is_noop():
    import mcp_servers.sigma_server as sigma_mod
    mgr = _FakeMcpManager(tools=[_FINDINGS_TOOL])
    with patch.object(sigma_mod, "_PYSIGMA_AVAILABLE", True), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_sigma_sweep("owner1", task_id="task-1", prompt="{}")


@pytest.mark.asyncio
async def test_first_run_establishes_baseline_no_finding():
    import mcp_servers.sigma_server as sigma_mod
    mgr = _FakeMcpManager(tools=[_FINDINGS_TOOL])
    prompt = json.dumps({"rules": ["suspicious-logins"]})
    with patch.object(sigma_mod, "_PYSIGMA_AVAILABLE", True), \
         patch.object(sigma_mod, "_convert_rule", return_value=(["query1"], None)), \
         patch.object(sigma_mod, "_os_search", return_value=_search_result("doc-1")), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_sigma_sweep("owner1", task_id="task-1", prompt=prompt)
    assert not any(c[0] == "mcp__findings__finding_index" for c in mgr.calls)


@pytest.mark.asyncio
async def test_second_run_with_drift_files_finding_and_notifies():
    import mcp_servers.sigma_server as sigma_mod
    prompt = json.dumps({"rules": ["suspicious-logins"], "engagement_id": "eng-1"})
    mgr = _FakeMcpManager(tools=[_FINDINGS_TOOL])
    with patch.object(sigma_mod, "_PYSIGMA_AVAILABLE", True), \
         patch.object(sigma_mod, "_convert_rule", return_value=(["query1"], None)), \
         patch.object(sigma_mod, "_os_search", return_value=_search_result("doc-1")), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_sigma_sweep("owner1", task_id="task-1", prompt=prompt)

    mgr2 = _FakeMcpManager(tools=[_FINDINGS_TOOL])
    mock_dispatch = AsyncMock(return_value={"browser_sent": True})
    with patch.object(sigma_mod, "_PYSIGMA_AVAILABLE", True), \
         patch.object(sigma_mod, "_convert_rule", return_value=(["query1"], None)), \
         patch.object(sigma_mod, "_os_search", return_value=_search_result("doc-1", "doc-2")), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr2), \
         patch("routes.note_routes.dispatch_reminder", mock_dispatch), \
         patch("src.event_bus.fire_event") as mock_fire_event:
        result, success = await action_sigma_sweep("owner1", task_id="task-1", prompt=prompt)

    assert success is True
    assert "suspicious-logins" in result
    finding_calls = [c for c in mgr2.calls if c[0] == "mcp__findings__finding_index"]
    assert len(finding_calls) == 1
    assert finding_calls[0][1]["engagement"] == "eng-1"
    mock_dispatch.assert_awaited_once()
    mock_fire_event.assert_called_once_with("security_finding_added", "owner1")


@pytest.mark.asyncio
async def test_convert_error_reports_error_not_crash():
    import mcp_servers.sigma_server as sigma_mod
    mgr = _FakeMcpManager(tools=[_FINDINGS_TOOL])
    prompt = json.dumps({"rules": ["broken-rule"]})
    with patch.object(sigma_mod, "_PYSIGMA_AVAILABLE", True), \
         patch.object(sigma_mod, "_convert_rule", return_value=(None, "[error:convert_error] bad rule")), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        result, success = await action_sigma_sweep("owner1", task_id="task-1", prompt=prompt)
    assert success is False
    assert "broken-rule" in result
