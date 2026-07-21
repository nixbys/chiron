"""Unit tests for the run_skill tool (src/tool_execution.py's pipeline
integration) — parsing the fenced-block JSON and dispatching into
src/pipeline_engine.py."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src import pipeline_engine as pe
from src import tool_execution as te


def test_parse_run_skill_happy_path():
    content = '{"skill": "full_recon", "inputs": {"target": "10.0.0.1"}, "confirmed": true}'
    skill, inputs, confirmed = te._parse_run_skill(content)
    assert skill == "full_recon"
    assert inputs == {"target": "10.0.0.1"}
    assert confirmed is True


def test_parse_run_skill_defaults_on_missing_fields():
    skill, inputs, confirmed = te._parse_run_skill('{"skill": "full_recon"}')
    assert skill == "full_recon"
    assert inputs == {}
    assert confirmed is False


def test_parse_run_skill_malformed_json_returns_empty_skill():
    skill, inputs, confirmed = te._parse_run_skill("not json")
    assert skill == ""


@pytest.mark.asyncio
async def test_run_skill_tool_requires_skill_name():
    result = await te._run_skill_tool('{"inputs": {}}')
    assert result["exit_code"] == 1
    assert "skill" in result["error"]


@pytest.mark.asyncio
async def test_run_skill_tool_no_mcp_manager(monkeypatch):
    monkeypatch.setattr(te, "get_mcp_manager", lambda: None)
    result = await te._run_skill_tool('{"skill": "full_recon"}')
    assert result["exit_code"] == 1
    assert "MCP manager" in result["error"]


@pytest.mark.asyncio
async def test_run_skill_tool_success_formats_step_output(monkeypatch):
    manager = MagicMock()
    monkeypatch.setattr(te, "get_mcp_manager", lambda: manager)

    async def _fake_run(skill_name, inputs, mcp_manager, progress_cb=None, confirmed=False, **kw):
        assert skill_name == "full_recon"
        assert mcp_manager is manager
        return {
            "steps": {"port_scan": {"stdout": "22/tcp open ssh", "stderr": "", "exit_code": 0}},
            "skipped": ["web_enum"],
        }

    monkeypatch.setattr(pe, "run", _fake_run)

    result = await te._run_skill_tool('{"skill": "full_recon", "confirmed": true}')
    assert result["exit_code"] == 0
    assert "22/tcp open ssh" in result["stdout"]
    assert "web_enum" in result["stdout"]


@pytest.mark.asyncio
async def test_run_skill_tool_nonzero_exit_on_step_failure(monkeypatch):
    manager = MagicMock()
    monkeypatch.setattr(te, "get_mcp_manager", lambda: manager)

    async def _fake_run(*a, **kw):
        return {"steps": {"a": {"stdout": "", "stderr": "boom", "exit_code": 1}}, "skipped": []}

    monkeypatch.setattr(pe, "run", _fake_run)
    result = await te._run_skill_tool('{"skill": "full_recon", "confirmed": true}')
    assert result["exit_code"] == 1


@pytest.mark.asyncio
async def test_run_skill_tool_confirmation_required_surfaces_prompt(monkeypatch):
    manager = MagicMock()
    monkeypatch.setattr(te, "get_mcp_manager", lambda: manager)

    async def _fake_run(*a, **kw):
        raise pe.ConfirmationRequired("Confirm authorization for 10.0.0.1.")

    monkeypatch.setattr(pe, "run", _fake_run)
    result = await te._run_skill_tool('{"skill": "full_recon"}')
    assert result["exit_code"] == 1
    assert "Confirm authorization for 10.0.0.1." in result["error"]
    assert "confirmed" in result["error"]


@pytest.mark.asyncio
async def test_run_skill_tool_pipeline_error_surfaces_message(monkeypatch):
    manager = MagicMock()
    monkeypatch.setattr(te, "get_mcp_manager", lambda: manager)

    async def _fake_run(*a, **kw):
        raise pe.PipelineError("Unknown skill: 'nope'")

    monkeypatch.setattr(pe, "run", _fake_run)
    result = await te._run_skill_tool('{"skill": "nope"}')
    assert result["exit_code"] == 1
    assert "Unknown skill" in result["error"]


@pytest.mark.asyncio
async def test_run_skill_tool_forwards_progress_cb(monkeypatch):
    manager = MagicMock()
    monkeypatch.setattr(te, "get_mcp_manager", lambda: manager)
    seen_cb = []

    async def _fake_run(skill_name, inputs, mcp_manager, progress_cb=None, confirmed=False, **kw):
        seen_cb.append(progress_cb)
        return {"steps": {}, "skipped": []}

    monkeypatch.setattr(pe, "run", _fake_run)
    cb = AsyncMock()
    await te._run_skill_tool('{"skill": "full_recon", "confirmed": true}', progress_cb=cb)
    assert seen_cb[0] is cb
