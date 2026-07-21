"""Tests for routes/orchestration_routes.py — pipeline list/run/poll endpoints."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException, Request

import routes.orchestration_routes as orch_routes
from routes.orchestration_routes import RunPipelineRequest, setup_orchestration_routes
from src import pipeline_engine as pe


def _handlers(mcp_manager):
    router = setup_orchestration_routes(mcp_manager)
    by_path = {}
    for route in router.routes:
        by_path.setdefault(route.path, {})[next(iter(route.methods - {"HEAD"}))] = route.endpoint
    return by_path


def _req():
    return Request(scope={"type": "http"})


@pytest.fixture(autouse=True)
def _bypass_admin(monkeypatch):
    monkeypatch.setattr(orch_routes, "require_admin", lambda r: None)


@pytest.fixture(autouse=True)
def _bypass_exec_token_check(monkeypatch):
    # Tested separately in tests/test_pipeline_engine.py; keep it out of the
    # way here so these tests focus on the route layer.
    monkeypatch.setenv("TOOLCHAIN_EXEC_MODE", "local")


@pytest.fixture(autouse=True)
def _clear_runs():
    orch_routes._runs.clear()
    yield
    orch_routes._runs.clear()


def _mcp_manager():
    manager = MagicMock()
    manager.get_all_tools.return_value = [
        {"server_id": "recon", "name": "nmap_scan", "qualified_name": "mcp__recon__nmap_scan"},
    ]
    manager.call_tool = AsyncMock(return_value={"stdout": "ok", "stderr": "", "exit_code": 0})
    return manager


async def _wait_until_done(run_id, timeout=2):
    for _ in range(200):
        if orch_routes._runs[run_id]["status"] != "running":
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"run {run_id} did not finish within {timeout}s")


def test_list_pipelines_includes_full_recon():
    handlers = _handlers(_mcp_manager())
    result = handlers["/api/orchestration/pipelines"]["GET"](_req())
    names = [p["name"] for p in result["pipelines"]]
    assert "full_recon" in names
    full_recon = next(p for p in result["pipelines"] if p["name"] == "full_recon")
    assert full_recon["requires_authorization"] is True
    assert full_recon["step_count"] == 4


@pytest.mark.asyncio
async def test_run_unknown_pipeline_404():
    handlers = _handlers(_mcp_manager())
    with pytest.raises(HTTPException) as exc_info:
        await handlers["/api/orchestration/pipelines/{name}/run"]["POST"](
            name="does_not_exist", body=RunPipelineRequest(), request=_req()
        )
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_run_and_poll_happy_path(monkeypatch):
    monkeypatch.setattr(
        pe,
        "load_skill",
        lambda name: {
            "name": "test_skill",
            "inputs": {},
            "steps": [{"id": "a", "tool": "nmap_scan", "args": {}}],
        },
    )
    manager = _mcp_manager()
    handlers = _handlers(manager)

    started = await handlers["/api/orchestration/pipelines/{name}/run"]["POST"](
        name="test_skill", body=RunPipelineRequest(inputs={}, confirmed=True), request=_req()
    )
    run_id = started["run_id"]
    assert started["status"] == "running"

    await _wait_until_done(run_id)

    polled = handlers["/api/orchestration/runs/{run_id}"]["GET"](run_id=run_id, request=_req())
    assert polled["status"] == "done"
    assert polled["steps"]["a"]["exit_code"] == 0


@pytest.mark.asyncio
async def test_run_requiring_authorization_without_confirm(monkeypatch):
    monkeypatch.setattr(
        pe,
        "load_skill",
        lambda name: {
            "name": "test_skill",
            "inputs": {},
            "authorization_prompt": "Confirm it.",
            "steps": [{"id": "a", "tool": "nmap_scan", "args": {}}],
        },
    )
    manager = _mcp_manager()
    handlers = _handlers(manager)

    started = await handlers["/api/orchestration/pipelines/{name}/run"]["POST"](
        name="test_skill", body=RunPipelineRequest(inputs={}, confirmed=False), request=_req()
    )
    run_id = started["run_id"]

    await _wait_until_done(run_id)

    polled = handlers["/api/orchestration/runs/{run_id}"]["GET"](run_id=run_id, request=_req())
    assert polled["status"] == "needs_confirmation"
    assert "Confirm it." in polled["prompt"]
    manager.call_tool.assert_not_awaited()


def test_get_unknown_run_404():
    handlers = _handlers(_mcp_manager())
    with pytest.raises(HTTPException) as exc_info:
        handlers["/api/orchestration/runs/{run_id}"]["GET"](run_id="nope", request=_req())
    assert exc_info.value.status_code == 404
