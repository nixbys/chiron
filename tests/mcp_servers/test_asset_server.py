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
async def test_asset_add_and_list_by_engagement(tmp_data_dir):
    mod = tmp_data_dir
    await mod.call_tool("asset_add", {"ip": "10.0.0.5", "engagement_id": "eng-1"})
    await mod.call_tool("asset_add", {"ip": "10.0.0.6", "engagement_id": "eng-2"})

    results = await mod.call_tool("asset_list", {"engagement_id": "eng-1"})
    text = results[0].text
    assert "10.0.0.5" in text
    assert "10.0.0.6" not in text


@pytest.mark.asyncio
async def test_finding_add_and_list_by_engagement(tmp_data_dir):
    mod = tmp_data_dir
    await mod.call_tool("finding_add", {
        "title": "Open SSH", "severity": "low", "engagement_id": "eng-1",
    })
    await mod.call_tool("finding_add", {
        "title": "Open RDP", "severity": "medium", "engagement_id": "eng-2",
    })

    results = await mod.call_tool("finding_list", {"engagement_id": "eng-1"})
    text = results[0].text
    assert "Open SSH" in text
    assert "Open RDP" not in text


@pytest.mark.asyncio
async def test_asset_add_preserves_engagement_id_on_update(tmp_data_dir):
    """A follow-up asset_add for the same IP with no engagement_id (e.g. a
    plain rescan) must not clear a previously-recorded engagement_id."""
    mod = tmp_data_dir
    await mod.call_tool("asset_add", {"ip": "10.0.0.7", "engagement_id": "eng-1"})
    await mod.call_tool("asset_add", {"ip": "10.0.0.7", "hostname": "rescanned"})

    results = await mod.call_tool("asset_list", {"engagement_id": "eng-1"})
    assert "10.0.0.7" in results[0].text


@pytest.mark.asyncio
async def test_engagement_id_migration_on_existing_db(tmp_path, monkeypatch):
    """A database created before the engagement_id columns existed must be
    transparently migrated on next open, not crash or lose data."""
    import importlib
    import sqlite3

    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    db_path = tmp_path / "assets.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Simulate a pre-migration schema (no engagement_id column).
    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        CREATE TABLE assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT, hostname TEXT, os TEXT,
            criticality TEXT DEFAULT 'medium', tags TEXT DEFAULT '[]',
            first_seen REAL, last_seen REAL, notes TEXT DEFAULT '',
            UNIQUE(ip)
        );
        INSERT INTO assets (ip, hostname, first_seen, last_seen) VALUES ('10.0.0.99', 'legacy', 1, 1);
    """)
    conn.commit()
    conn.close()

    import mcp_servers.asset_server as asset_mod
    importlib.reload(asset_mod)

    # Pre-existing row survives the migration.
    results = await asset_mod.call_tool("asset_list", {})
    assert "10.0.0.99" in results[0].text

    # New engagement-scoped writes work post-migration.
    await asset_mod.call_tool("asset_add", {"ip": "10.0.0.100", "engagement_id": "eng-1"})
    results = await asset_mod.call_tool("asset_list", {"engagement_id": "eng-1"})
    assert "10.0.0.100" in results[0].text


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


# ---- _export_data (export feature) -----------------------------------------


@pytest.mark.asyncio
async def test_export_data_returns_assets_services_and_findings(tmp_data_dir):
    mod = tmp_data_dir
    await mod.call_tool("asset_add", {"ip": "10.0.0.10", "hostname": "host10"})
    await mod.call_tool("service_add", {"ip": "10.0.0.10", "port": 22, "service_name": "ssh"})
    await mod.call_tool("finding_add", {"ip": "10.0.0.10", "title": "Open SSH", "severity": "low"})

    data = mod._export_data()
    assert len(data["assets"]) == 1
    assert data["assets"][0]["ip"] == "10.0.0.10"
    assert len(data["services"]) == 1
    assert data["services"][0]["asset_ip"] == "10.0.0.10"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["title"] == "Open SSH"


@pytest.mark.asyncio
async def test_export_data_filters_by_engagement_id(tmp_data_dir):
    mod = tmp_data_dir
    await mod.call_tool("asset_add", {"ip": "10.0.0.11", "engagement_id": "eng-1"})
    await mod.call_tool("asset_add", {"ip": "10.0.0.12", "engagement_id": "eng-2"})

    scoped = mod._export_data(engagement_id="eng-1")
    assert len(scoped["assets"]) == 1
    assert scoped["assets"][0]["ip"] == "10.0.0.11"

    unscoped = mod._export_data()
    assert len(unscoped["assets"]) == 2


def test_export_data_empty_store(tmp_data_dir):
    mod = tmp_data_dir
    data = mod._export_data()
    assert data == {"assets": [], "services": [], "findings": []}
