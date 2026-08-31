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

from src.builtin_actions import TaskNoop, action_scope_violation_check


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
