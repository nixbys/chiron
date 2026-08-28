"""Unit tests for src.builtin_actions.action_verify_remediation.

Mocks the MCP manager (no real subprocess servers), findings_server's
_req/_ensure_index (no real OpenSearch), and intel_server's _shodan_fetch.
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.builtin_actions import TaskNoop, action_verify_remediation


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
_UPDATE_TOOL = {"name": "finding_update_status", "qualified_name": "mcp__findings__finding_update_status", "is_disabled": False}


def _search_response(hits):
    return {"hits": {"hits": hits}}


def _hit(doc_id, title, description, engagement=None):
    return {"_id": doc_id, "_source": {"title": title, "description": description, "engagement": engagement}}


@pytest.mark.asyncio
async def test_invalid_json_prompt():
    result, success = await action_verify_remediation("owner1", prompt="not json")
    assert success is False
    assert "JSON" in result


@pytest.mark.asyncio
async def test_no_remediated_findings_is_noop():
    import mcp_servers.findings_server as findings_mod
    mgr = _FakeMcpManager(tools=[_UPDATE_TOOL])
    with patch.object(findings_mod, "_ensure_index", return_value=None), \
         patch.object(findings_mod, "_req", return_value=_search_response([])), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        with pytest.raises(TaskNoop):
            await action_verify_remediation("owner1", prompt="{}")


@pytest.mark.asyncio
async def test_still_present_reopens_and_notifies():
    import mcp_servers.findings_server as findings_mod
    hits = [_hit("doc-1", "ports change on 192.0.2.1", "Added: ['22/tcp']  Removed: none", engagement="eng-1")]
    mgr = _FakeMcpManager(
        tools=[_NMAP_TOOL, _UPDATE_TOOL],
        call_results={"mcp__recon__nmap_scan": {"stdout": "22/tcp open ssh", "exit_code": 0}},
    )
    mock_dispatch = AsyncMock(return_value={"browser_sent": True})
    with patch.object(findings_mod, "_ensure_index", return_value=None), \
         patch.object(findings_mod, "_req", return_value=_search_response(hits)), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr), \
         patch("routes.note_routes.dispatch_reminder", mock_dispatch), \
         patch("src.event_bus.fire_event") as mock_fire_event, \
         patch("mcp_servers.engagement_server._log_event") as mock_log_event:
        result, success = await action_verify_remediation("owner1", prompt="{}")

    assert success is True
    assert "22/tcp" in result
    update_calls = [c for c in mgr.calls if c[0] == "mcp__findings__finding_update_status"]
    assert len(update_calls) == 1
    assert update_calls[0][1]["doc_id"] == "doc-1"
    assert update_calls[0][1]["status"] == "open"
    mock_dispatch.assert_awaited_once()
    mock_fire_event.assert_called_once_with("security_finding_added", "owner1")
    mock_log_event.assert_called_once()


@pytest.mark.asyncio
async def test_no_longer_present_confirms_without_reopening():
    import mcp_servers.findings_server as findings_mod
    hits = [_hit("doc-2", "ports change on 192.0.2.1", "Added: ['443/tcp']  Removed: none", engagement="eng-1")]
    mgr = _FakeMcpManager(
        tools=[_NMAP_TOOL, _UPDATE_TOOL],
        call_results={"mcp__recon__nmap_scan": {"stdout": "22/tcp open ssh", "exit_code": 0}},  # 443 no longer open
    )
    with patch.object(findings_mod, "_ensure_index", return_value=None), \
         patch.object(findings_mod, "_req", return_value=_search_response(hits)), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr), \
         patch("mcp_servers.engagement_server._log_event") as mock_log_event:
        with pytest.raises(TaskNoop):
            await action_verify_remediation("owner1", prompt="{}")

    assert not any(c[0] == "mcp__findings__finding_update_status" for c in mgr.calls)
    mock_log_event.assert_called_once()
    assert "confirmed" in mock_log_event.call_args[0][2].lower()


@pytest.mark.asyncio
async def test_unparseable_finding_reports_error_not_crash():
    import mcp_servers.findings_server as findings_mod
    hits = [_hit("doc-3", "not a parseable title", "no added list here")]
    mgr = _FakeMcpManager(tools=[_UPDATE_TOOL])
    with patch.object(findings_mod, "_ensure_index", return_value=None), \
         patch.object(findings_mod, "_req", return_value=_search_response(hits)), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        result, success = await action_verify_remediation("owner1", prompt="{}")
    assert success is False
    assert "skipped" in result


@pytest.mark.asyncio
async def test_cve_check_uses_shodan_fetch_directly():
    import mcp_servers.findings_server as findings_mod
    hits = [_hit("doc-4", "cve change on 192.0.2.1", "Added: ['CVE-2024-0002']  Removed: none", engagement="eng-1")]
    mgr = _FakeMcpManager(tools=[_UPDATE_TOOL])
    mock_dispatch = AsyncMock(return_value={})
    with patch.object(findings_mod, "_ensure_index", return_value=None), \
         patch.object(findings_mod, "_req", return_value=_search_response(hits)), \
         patch("mcp_servers.intel_server._shodan_fetch", return_value={"vulns": {"CVE-2024-0001": {}, "CVE-2024-0002": {}}}), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr), \
         patch("routes.note_routes.dispatch_reminder", mock_dispatch), \
         patch("src.event_bus.fire_event"):
        result, success = await action_verify_remediation("owner1", prompt="{}")
    assert success is True
    assert "CVE-2024-0002" in result


@pytest.mark.asyncio
async def test_opensearch_query_failure_reports_error_not_crash():
    import mcp_servers.findings_server as findings_mod
    mgr = _FakeMcpManager(tools=[])
    with patch.object(findings_mod, "_ensure_index", return_value=None), \
         patch.object(findings_mod, "_req", side_effect=RuntimeError("connection refused")), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        result, success = await action_verify_remediation("owner1", prompt="{}")
    assert success is False
    assert "connection refused" in result
