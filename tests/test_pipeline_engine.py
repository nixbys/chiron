"""Unit tests for src/pipeline_engine.py — parses skills/*.yaml-shaped dicts
in-memory (no real file I/O) and mocks mcp_manager.call_tool."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from src import pipeline_engine as pe


def _mcp_manager(tools=None, call_tool_side_effect=None):
    manager = MagicMock()
    manager.get_all_tools.return_value = tools or [
        {"server_id": "recon", "name": "nmap_scan", "qualified_name": "mcp__recon__nmap_scan"},
        {"server_id": "web_vuln", "name": "gobuster_dir", "qualified_name": "mcp__web_vuln__gobuster_dir"},
        {"server_id": "pdf", "name": "generate_report", "qualified_name": "mcp__pdf__generate_report"},
    ]
    manager.call_tool = AsyncMock(side_effect=call_tool_side_effect)
    return manager


@pytest.fixture(autouse=True)
def _default_env(monkeypatch):
    # Keep the EXEC_API_TOKEN fail-closed precondition out of the way for
    # tests that aren't specifically exercising it.
    monkeypatch.setenv("TOOLCHAIN_EXEC_MODE", "local")


def _skill(**overrides):
    base = {
        "name": "test_skill",
        "inputs": {"target": {"type": "string", "required": True}},
        "steps": [
            {"id": "a", "tool": "nmap_scan", "args": {"target": "{{ target }}"}},
            {"id": "b", "tool": "gobuster_dir", "args": {"target": "{{ target }}"}},
        ],
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_independent_steps_run_concurrently(monkeypatch):
    skill = _skill()
    monkeypatch.setattr(pe, "load_skill", lambda name: skill)

    started = asyncio.Event()
    release = asyncio.Event()
    concurrent_seen = False

    async def _call_tool(qualified_name, args):
        nonlocal concurrent_seen
        if not started.is_set():
            started.set()
            # First caller waits for the second to also have started.
            try:
                await asyncio.wait_for(release.wait(), timeout=2)
                concurrent_seen = True
            except asyncio.TimeoutError:
                pass
        else:
            release.set()
        return {"stdout": qualified_name, "stderr": "", "exit_code": 0}

    manager = _mcp_manager(call_tool_side_effect=_call_tool)
    result = await pe.run("test_skill", {"target": "10.0.0.1"}, manager)

    assert concurrent_seen, "independent steps should have run concurrently, not sequentially"
    assert result["steps"]["a"]["exit_code"] == 0
    assert result["steps"]["b"]["exit_code"] == 0


@pytest.mark.asyncio
async def test_dependent_step_waits_and_receives_rendered_output(monkeypatch):
    skill = _skill(
        steps=[
            {"id": "a", "tool": "nmap_scan", "args": {"target": "{{ target }}"}},
            {
                "id": "b",
                "tool": "gobuster_dir",
                "args": {"summary": "prior: {{ steps.a.stdout }}"},
            },
        ]
    )
    monkeypatch.setattr(pe, "load_skill", lambda name: skill)

    calls = []

    async def _call_tool(qualified_name, args):
        calls.append((qualified_name, dict(args)))
        if qualified_name.endswith("nmap_scan"):
            return {"stdout": "22/tcp open", "stderr": "", "exit_code": 0}
        return {"stdout": "done", "stderr": "", "exit_code": 0}

    manager = _mcp_manager(call_tool_side_effect=_call_tool)
    result = await pe.run("test_skill", {"target": "10.0.0.1"}, manager)

    assert result["steps"]["a"]["stdout"] == "22/tcp open"
    b_call = next(c for c in calls if c[0].endswith("gobuster_dir"))
    assert b_call[1]["summary"] == "prior: 22/tcp open"


@pytest.mark.asyncio
async def test_condition_false_skips_step(monkeypatch):
    skill = _skill(
        steps=[
            {"id": "a", "tool": "nmap_scan", "args": {"target": "{{ target }}"}},
            {
                "id": "b",
                "tool": "gobuster_dir",
                "condition": "{{ false }}",
                "args": {"target": "{{ target }}"},
            },
        ]
    )
    monkeypatch.setattr(pe, "load_skill", lambda name: skill)
    manager = _mcp_manager(call_tool_side_effect=lambda q, a: {"stdout": "ok", "stderr": "", "exit_code": 0})

    result = await pe.run("test_skill", {"target": "10.0.0.1"}, manager)

    assert "b" not in result["steps"]
    assert result["skipped"] == ["b"]
    manager.call_tool.assert_awaited_once()


@pytest.mark.asyncio
async def test_authorization_prompt_requires_confirmation(monkeypatch):
    skill = _skill(authorization_prompt="Confirm authorization for {{ target }}.")
    monkeypatch.setattr(pe, "load_skill", lambda name: skill)
    manager = _mcp_manager(call_tool_side_effect=lambda q, a: {"stdout": "", "stderr": "", "exit_code": 0})

    with pytest.raises(pe.ConfirmationRequired) as exc_info:
        await pe.run("test_skill", {"target": "10.0.0.1"}, manager, confirmed=False)

    assert "10.0.0.1" in exc_info.value.prompt
    manager.call_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_authorization_prompt_confirmed_runs(monkeypatch):
    skill = _skill(authorization_prompt="Confirm authorization for {{ target }}.")
    monkeypatch.setattr(pe, "load_skill", lambda name: skill)
    manager = _mcp_manager(call_tool_side_effect=lambda q, a: {"stdout": "ok", "stderr": "", "exit_code": 0})

    result = await pe.run("test_skill", {"target": "10.0.0.1"}, manager, confirmed=True)
    assert result["steps"]["a"]["exit_code"] == 0


@pytest.mark.asyncio
async def test_missing_required_input_raises(monkeypatch):
    skill = _skill()
    monkeypatch.setattr(pe, "load_skill", lambda name: skill)
    manager = _mcp_manager()

    with pytest.raises(pe.PipelineError, match="target"):
        await pe.run("test_skill", {}, manager)


@pytest.mark.asyncio
async def test_cycle_detection_raises(monkeypatch):
    skill = _skill(
        steps=[
            {"id": "a", "tool": "nmap_scan", "args": {"x": "{{ steps.b.stdout }}"}},
            {"id": "b", "tool": "gobuster_dir", "args": {"x": "{{ steps.a.stdout }}"}},
        ]
    )
    monkeypatch.setattr(pe, "load_skill", lambda name: skill)
    manager = _mcp_manager()

    with pytest.raises(pe.PipelineError, match="Cycle"):
        await pe.run("test_skill", {"target": "10.0.0.1"}, manager)


@pytest.mark.asyncio
async def test_exec_api_token_placeholder_blocks_container_mode(monkeypatch):
    monkeypatch.setenv("TOOLCHAIN_EXEC_MODE", "container")
    monkeypatch.delenv("EXEC_API_TOKEN", raising=False)
    skill = _skill()
    monkeypatch.setattr(pe, "load_skill", lambda name: skill)
    manager = _mcp_manager()

    with pytest.raises(pe.PipelineError, match="EXEC_API_TOKEN"):
        await pe.run("test_skill", {"target": "10.0.0.1"}, manager)
    manager.call_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_exec_api_token_check_skipped_in_local_mode(monkeypatch):
    monkeypatch.setenv("TOOLCHAIN_EXEC_MODE", "local")
    monkeypatch.delenv("EXEC_API_TOKEN", raising=False)
    skill = _skill()
    monkeypatch.setattr(pe, "load_skill", lambda name: skill)
    manager = _mcp_manager(call_tool_side_effect=lambda q, a: {"stdout": "ok", "stderr": "", "exit_code": 0})

    result = await pe.run("test_skill", {"target": "10.0.0.1"}, manager)
    assert result["steps"]["a"]["exit_code"] == 0


@pytest.mark.asyncio
async def test_unknown_tool_name_raises_result_error(monkeypatch):
    skill = _skill(steps=[{"id": "a", "tool": "not_a_real_tool", "args": {}}])
    monkeypatch.setattr(pe, "load_skill", lambda name: skill)
    manager = _mcp_manager()

    result = await pe.run("test_skill", {"target": "10.0.0.1"}, manager)
    assert result["steps"]["a"]["exit_code"] == 1
    assert "not found" in result["steps"]["a"]["stderr"]


def test_regex_extract_filter():
    assert pe._regex_extract("Scan started. ID: abc123\nOther text", r"ID: (\S+)") == "abc123"
    assert pe._regex_extract("no id here", r"ID: (\S+)") == ""
