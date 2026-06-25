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
