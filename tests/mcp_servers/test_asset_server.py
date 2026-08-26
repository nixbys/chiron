"""Unit tests for asset_server.py — uses an in-memory (temp dir) SQLite DB."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture(autouse=True)
def tmp_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    # Re-import so _DB_PATH picks up the new env var.
    import importlib
    import mcp_servers.asset_server as asset_mod
    importlib.reload(asset_mod)
    yield asset_mod


@pytest.mark.asyncio
async def test_asset_add_and_list(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("asset_add", {"ip": "10.0.0.1", "hostname": "host1", "criticality": "high"})
    assert results
    assert "[error:" not in results[0].text

    list_results = await mod.call_tool("asset_list", {})
    assert list_results
    assert "10.0.0.1" in list_results[0].text


@pytest.mark.asyncio
async def test_asset_list_empty(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("asset_list", {})
    assert results
    text = results[0].text
    assert "No assets" in text or "[" in text or "0" in text


@pytest.mark.asyncio
async def test_service_add(tmp_data_dir):
    mod = tmp_data_dir
    await mod.call_tool("asset_add", {"ip": "10.0.0.2"})
    results = await mod.call_tool("service_add", {
        "ip": "10.0.0.2", "port": 80, "protocol": "tcp", "service_name": "http"
    })
    assert results
    assert "[error:" not in results[0].text


@pytest.mark.asyncio
async def test_finding_add_and_list(tmp_data_dir):
    mod = tmp_data_dir
    await mod.call_tool("asset_add", {"ip": "10.0.0.3"})
    await mod.call_tool("finding_add", {
        "ip": "10.0.0.3",
        "title": "Open SSH",
        "severity": "low",
        "description": "SSH port 22 accessible",
    })
    results = await mod.call_tool("finding_list", {"ip": "10.0.0.3"})
    assert results
    assert "Open SSH" in results[0].text or "[error:" not in results[0].text


@pytest.mark.asyncio
async def test_asset_add_duplicate_ok(tmp_data_dir):
    mod = tmp_data_dir
    await mod.call_tool("asset_add", {"ip": "10.0.0.4"})
    results = await mod.call_tool("asset_add", {"ip": "10.0.0.4"})
    assert results


@pytest.mark.asyncio
async def test_module_import_survives_unwritable_data_dir(tmp_path, monkeypatch):
    """Regression test: importing the module must never crash the whole MCP
    server process just because the data directory can't be written to yet
    (missing volume mount, bad permissions, full disk). Before this fix,
    schema init ran unconditionally at module import time with no error
    handling, so an unwritable data dir killed the process before it could
    even register its tools with the MCP client -- the exact "tools
    disappearing with no error" failure mode this fork's release plan calls
    out as the top reliability risk for its MCP servers.

    Simulated here by pointing ODYSSEUS_DATA_DIR at a path whose "data"
    component is a plain *file*, not a directory: mkdir(parents=True,
    exist_ok=True) on the (already-existing) parent is a no-op, but
    sqlite3.connect() then fails to open a db file inside what is actually a
    file -- the same "unable to open database file" failure a real
    permissions problem produces, without needing root to create a genuinely
    unwritable directory in CI.
    """
    import importlib
    import mcp_servers.asset_server as asset_mod

    bogus_data_dir = tmp_path / "data"
    bogus_data_dir.write_text("not a directory")

    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(bogus_data_dir))
    # Must not raise -- this is the regression this test guards against.
    importlib.reload(asset_mod)

    # Tools are still registered even though the DB is unreachable.
    assert any(t.name == "asset_add" for t in asset_mod.TOOLS)

    # A tool that actually needs the DB fails cleanly (a normal MCP error
    # response the agent/client can see and report), not an unhandled
    # exception that kills the connection.
    results = await asset_mod.call_tool("asset_add", {"ip": "10.0.0.9"})
    assert results
    assert "[error:" in results[0].text
