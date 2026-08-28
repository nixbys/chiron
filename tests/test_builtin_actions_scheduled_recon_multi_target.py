"""Unit tests for action_scheduled_recon's multi-target support (Phase 1
checkpoint D): "targets" list, "use_engagement_assets" resolution, and
"target"/"targets" merging. Mirrors
tests/test_builtin_actions_scheduled_recon.py's fixture pattern.
"""

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.builtin_actions import TaskNoop, action_scheduled_recon


class _FakeMcpManager:
    """Like the fixture in test_builtin_actions_scheduled_recon.py, but
    call_results may map a qualified_name to either a fixed result dict or
    a callable(args) -> result dict, so different targets can get different
    scan output from the same tool."""

    def __init__(self, tools, call_results=None):
        self._tools = tools
        self._call_results = call_results or {}
        self.calls = []

    def get_all_tools(self):
        return self._tools

    async def call_tool(self, qualified_name, args):
        self.calls.append((qualified_name, args))
        entry = self._call_results.get(qualified_name, {"stdout": "", "stderr": "", "exit_code": 0})
        return entry(args) if callable(entry) else entry


_NMAP_TOOL = {"name": "nmap_scan", "qualified_name": "mcp__recon__nmap_scan", "is_disabled": False}
_ASSET_LIST_TOOL = {"name": "asset_list", "qualified_name": "mcp__asset__asset_list", "is_disabled": False}
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


def _ports_by_target(mapping):
    def _handler(args):
        return {"stdout": mapping.get(args["target"], ""), "exit_code": 0}
    return _handler


@pytest.mark.asyncio
async def test_targets_list_and_target_string_are_merged():
    mgr = _FakeMcpManager(
        tools=[_NMAP_TOOL, _FINDINGS_TOOL],
        call_results={"mcp__recon__nmap_scan": _ports_by_target({"host-a": "22/tcp open ssh", "host-b": "80/tcp open http"})},
    )
    prompt = json.dumps({"target": "host-a", "targets": ["host-b"], "checks": ["ports"]})
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_scheduled_recon("owner1", task_id="task-1", prompt=prompt)
    scanned = {c[1]["target"] for c in mgr.calls if c[0] == "mcp__recon__nmap_scan"}
    assert scanned == {"host-a", "host-b"}


@pytest.mark.asyncio
async def test_multi_target_drift_batches_one_reminder():
    prompt = json.dumps({"targets": ["host-a", "host-b"], "checks": ["ports"]})
    mgr = _FakeMcpManager(
        tools=[_NMAP_TOOL, _FINDINGS_TOOL],
        call_results={"mcp__recon__nmap_scan": _ports_by_target({"host-a": "22/tcp open ssh", "host-b": "22/tcp open ssh"})},
    )
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_scheduled_recon("owner1", task_id="task-1", prompt=prompt)

    # Second run: host-a gains a port, host-b stays the same.
    mgr2 = _FakeMcpManager(
        tools=[_NMAP_TOOL, _FINDINGS_TOOL],
        call_results={"mcp__recon__nmap_scan": _ports_by_target({
            "host-a": "22/tcp open ssh\n443/tcp open https",
            "host-b": "22/tcp open ssh",
        })},
    )
    mock_dispatch = AsyncMock(return_value={"browser_sent": True})
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr2), \
         patch("routes.note_routes.dispatch_reminder", mock_dispatch), \
         patch("src.event_bus.fire_event") as mock_fire_event:
        result, success = await action_scheduled_recon("owner1", task_id="task-1", prompt=prompt)

    assert success is True
    assert "host-a" in result
    assert "443/tcp" in result
    finding_calls = [c for c in mgr2.calls if c[0] == "mcp__findings__finding_index"]
    assert len(finding_calls) == 1  # only host-a drifted
    # One batched reminder for the whole run, not one per target.
    mock_dispatch.assert_awaited_once()
    mock_fire_event.assert_called_once_with("security_finding_added", "owner1")


@pytest.mark.asyncio
async def test_use_engagement_assets_resolves_targets_from_asset_list():
    asset_table = (
        "IP                 Hostname                       OS                   Criticality Tags\n"
        + "-" * 90 + "\n"
        "192.0.2.10         web1                           Linux                high        \n"
        "192.0.2.20         web2                           Linux                medium      \n"
    )
    mgr = _FakeMcpManager(
        tools=[_NMAP_TOOL, _ASSET_LIST_TOOL, _FINDINGS_TOOL],
        call_results={
            "mcp__asset__asset_list": {"stdout": asset_table, "exit_code": 0},
            "mcp__recon__nmap_scan": _ports_by_target({"192.0.2.10": "22/tcp open ssh", "192.0.2.20": "22/tcp open ssh"}),
        },
    )
    prompt = json.dumps({"use_engagement_assets": True, "engagement_id": "eng-1", "checks": ["ports"]})
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_scheduled_recon("owner1", task_id="task-1", prompt=prompt)
    scanned = {c[1]["target"] for c in mgr.calls if c[0] == "mcp__recon__nmap_scan"}
    assert scanned == {"192.0.2.10", "192.0.2.20"}


@pytest.mark.asyncio
async def test_use_engagement_assets_requires_engagement_id():
    mgr = _FakeMcpManager(tools=[])
    prompt = json.dumps({"use_engagement_assets": True, "checks": ["ports"]})
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        result, success = await action_scheduled_recon("owner1", task_id="task-1", prompt=prompt)
    assert success is False
    assert "engagement_id" in result


@pytest.mark.asyncio
async def test_targets_must_be_a_list():
    mgr = _FakeMcpManager(tools=[])
    prompt = json.dumps({"targets": "not-a-list", "checks": ["ports"]})
    with patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        result, success = await action_scheduled_recon("owner1", task_id="task-1", prompt=prompt)
    assert success is False
    assert "array" in result
