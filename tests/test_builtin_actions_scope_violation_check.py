"""Unit tests for src.builtin_actions.action_scope_violation_check.

Seeds mcp_servers/audit_server.py's SQLite store directly (temp dir) via
common.py's own writer, matching how the real audit.db is actually
populated, plus mocks reminder dispatch."""

import importlib
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import src.builtin_actions as ba_mod
from src.builtin_actions import TaskNoop, action_scope_violation_check


class _FakeMcpManager:
    """Same shape test_builtin_actions_watchlist_check.py's own fake uses."""

    def __init__(self):
        self.calls = []

    async def call_tool(self, qualified_name, args):
        self.calls.append((qualified_name, args))
        return {"stdout": "ok", "exit_code": 0}

    def get_all_tools(self):
        return [{"name": "finding_index", "qualified_name": "mcp__findings__finding_index", "is_disabled": False}]


@pytest.fixture(autouse=True)
def tmp_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    import mcp_servers.common as common_mod
    import mcp_servers.audit_server as audit_mod
    importlib.reload(common_mod)
    importlib.reload(audit_mod)
    yield audit_mod, common_mod


@pytest.mark.asyncio
async def test_no_violations_raises_noop(tmp_data_dir):
    with pytest.raises(TaskNoop, match="no new scope violations"):
        await action_scope_violation_check("owner1", task_id="task-1")


@pytest.mark.asyncio
async def test_first_run_establishes_baseline_silently(tmp_data_dir):
    """Same precedent as action_watchlist_check/action_scheduled_recon: a
    brand-new task shouldn't immediately re-alert on an engagement's whole
    pre-existing violation history."""
    _, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")

    mock_dispatch = AsyncMock()
    with patch("routes.note_routes.dispatch_reminder", mock_dispatch):
        with pytest.raises(TaskNoop, match="baseline established"):
            await action_scope_violation_check("owner1", task_id="task-1")
    mock_dispatch.assert_not_awaited()


@pytest.mark.asyncio
async def test_second_run_with_new_violation_notifies(tmp_data_dir):
    audit_mod, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    with pytest.raises(TaskNoop):
        await action_scope_violation_check("owner1", task_id="task-1")

    common_mod._log_invocation("nmap_scan", ["9.9.9.9"], "n/a", None, "scope_override", "client approved", engagement_id="eng-1")

    mock_dispatch = AsyncMock(return_value={"browser_sent": True})
    with patch("routes.note_routes.dispatch_reminder", mock_dispatch):
        summary, success = await action_scope_violation_check("owner1", task_id="task-1")

    assert success is True
    assert "9.9.9.9" in summary
    assert "scope_override" in summary
    assert "8.8.8.8" not in summary  # already covered by the baseline run
    mock_dispatch.assert_awaited_once()
    assert mock_dispatch.call_args.kwargs["title"] == "Engagement scope violation(s) detected"


@pytest.mark.asyncio
async def test_checkpoint_advances_so_the_same_violation_is_not_repeated(tmp_data_dir):
    audit_mod, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    with pytest.raises(TaskNoop):  # baseline
        await action_scope_violation_check("owner1", task_id="task-1")

    common_mod._log_invocation("nmap_scan", ["9.9.9.9"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    with patch("routes.note_routes.dispatch_reminder", AsyncMock()):
        await action_scope_violation_check("owner1", task_id="task-1")

    with pytest.raises(TaskNoop, match="no new scope violations"):
        await action_scope_violation_check("owner1", task_id="task-1")


@pytest.mark.asyncio
async def test_engagement_filter_ignores_other_engagements(tmp_data_dir):
    _, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    with pytest.raises(TaskNoop):  # baseline
        await action_scope_violation_check("owner1", task_id="task-1", prompt='{"engagement_id": "eng-2"}')

    common_mod._log_invocation("nmap_scan", ["9.9.9.9"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    with pytest.raises(TaskNoop, match="no new scope violations"):
        await action_scope_violation_check("owner1", task_id="task-1", prompt='{"engagement_id": "eng-2"}')


@pytest.mark.asyncio
async def test_checkpoints_are_independent_per_task(tmp_data_dir):
    """Two scheduled tasks (e.g. one per engagement) don't clobber each
    other's checkpoint state."""
    _, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    with pytest.raises(TaskNoop, match="baseline established"):
        await action_scope_violation_check("owner1", task_id="task-A")
    # A different task has never run -- it still sees that same row as new
    # (and, being its own first run, treats it as its own baseline too).
    with pytest.raises(TaskNoop, match="baseline established"):
        await action_scope_violation_check("owner1", task_id="task-B")


@pytest.mark.asyncio
async def test_invalid_prompt_json_returns_error(tmp_data_dir):
    summary, success = await action_scope_violation_check("owner1", task_id="task-1", prompt="not json")
    assert success is False
    assert "JSON" in summary


@pytest.mark.asyncio
async def test_dispatch_failure_does_not_crash_the_action(tmp_data_dir):
    """A reminder-dispatch failure must not prevent the checkpoint from
    advancing or the action from reporting success -- same
    best-effort-notification pattern action_watchlist_check uses."""
    _, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    with pytest.raises(TaskNoop):  # baseline
        await action_scope_violation_check("owner1", task_id="task-1")

    common_mod._log_invocation("nmap_scan", ["9.9.9.9"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    with patch("routes.note_routes.dispatch_reminder", AsyncMock(side_effect=RuntimeError("smtp down"))):
        summary, success = await action_scope_violation_check("owner1", task_id="task-1")
    assert success is True
    assert "9.9.9.9" in summary


# ---- Escalation (Phase J) -------------------------------------------------


@pytest.mark.asyncio
async def test_escalation_fires_when_threshold_crossed(tmp_data_dir):
    """Default threshold is 3 in a 24h window: baseline run seeds 1
    (silent), second run adds 2 more -- total 3 crosses the threshold."""
    _, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    with pytest.raises(TaskNoop):  # baseline
        await action_scope_violation_check("owner1", task_id="task-1")

    common_mod._log_invocation("nmap_scan", ["9.9.9.9"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    common_mod._log_invocation("nmap_scan", ["1.2.3.4"], "n/a", None, "scope_override", "approved", engagement_id="eng-1")

    mgr = _FakeMcpManager()
    with patch("routes.note_routes.dispatch_reminder", AsyncMock()), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr), \
         patch("mcp_servers.engagement_server._log_event") as mock_log_event:
        summary, success = await action_scope_violation_check("owner1", task_id="task-1")

    assert success is True
    assert "Pattern escalation" in summary
    assert "eng-1" in summary
    finding_calls = [c for c in mgr.calls if c[0] == "mcp__findings__finding_index"]
    assert len(finding_calls) == 1
    assert finding_calls[0][1]["engagement"] == "eng-1"
    assert finding_calls[0][1]["severity"] == "medium"
    assert finding_calls[0][1]["tags"] == ["process", "scope-deviation"]
    mock_log_event.assert_called_once()
    assert mock_log_event.call_args[0][0] == "eng-1"
    assert mock_log_event.call_args[0][1] == "finding_added"


@pytest.mark.asyncio
async def test_escalation_does_not_fire_below_threshold(tmp_data_dir):
    _, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    with pytest.raises(TaskNoop):  # baseline
        await action_scope_violation_check("owner1", task_id="task-1")

    common_mod._log_invocation("nmap_scan", ["9.9.9.9"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")

    mgr = _FakeMcpManager()
    with patch("routes.note_routes.dispatch_reminder", AsyncMock()), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        summary, success = await action_scope_violation_check("owner1", task_id="task-1")

    assert success is True
    assert "Pattern escalation" not in summary
    assert mgr.calls == []


@pytest.mark.asyncio
async def test_escalation_does_not_refire_once_already_over_threshold(tmp_data_dir):
    """Once an engagement is already over threshold, a later run with one
    more new violation must not re-file another finding."""
    _, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    with pytest.raises(TaskNoop):  # baseline
        await action_scope_violation_check("owner1", task_id="task-1")

    common_mod._log_invocation("nmap_scan", ["9.9.9.9"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    common_mod._log_invocation("nmap_scan", ["1.2.3.4"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    mgr = _FakeMcpManager()
    with patch("routes.note_routes.dispatch_reminder", AsyncMock()), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        await action_scope_violation_check("owner1", task_id="task-1")  # crosses threshold, fires once
    assert len(mgr.calls) == 1

    common_mod._log_invocation("nmap_scan", ["5.5.5.5"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    with patch("routes.note_routes.dispatch_reminder", AsyncMock()), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        summary, success = await action_scope_violation_check("owner1", task_id="task-1")
    assert "Pattern escalation" not in summary
    assert len(mgr.calls) == 1  # unchanged -- no second finding


@pytest.mark.asyncio
async def test_escalation_disabled_when_threshold_is_zero(tmp_data_dir, monkeypatch):
    monkeypatch.setattr(ba_mod, "_SCOPE_VIOLATION_ESCALATION_THRESHOLD", 0)
    _, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    with pytest.raises(TaskNoop):  # baseline
        await action_scope_violation_check("owner1", task_id="task-1")

    for target in ("9.9.9.9", "1.2.3.4", "5.5.5.5"):
        common_mod._log_invocation("nmap_scan", [target], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")

    mgr = _FakeMcpManager()
    with patch("routes.note_routes.dispatch_reminder", AsyncMock()), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        summary, success = await action_scope_violation_check("owner1", task_id="task-1")
    assert "Pattern escalation" not in summary
    assert mgr.calls == []


@pytest.mark.asyncio
async def test_escalation_is_per_engagement(tmp_data_dir):
    """Two engagements each below threshold on their own don't combine to
    trigger escalation for either."""
    _, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    common_mod._log_invocation("nmap_scan", ["9.9.9.9"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-2")
    with pytest.raises(TaskNoop):  # baseline
        await action_scope_violation_check("owner1", task_id="task-1")

    common_mod._log_invocation("nmap_scan", ["1.2.3.4"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    common_mod._log_invocation("nmap_scan", ["5.5.5.5"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-2")

    mgr = _FakeMcpManager()
    with patch("routes.note_routes.dispatch_reminder", AsyncMock()), \
         patch("src.tool_utils.get_mcp_manager", return_value=mgr):
        summary, success = await action_scope_violation_check("owner1", task_id="task-1")
    assert "Pattern escalation" not in summary
    assert mgr.calls == []
