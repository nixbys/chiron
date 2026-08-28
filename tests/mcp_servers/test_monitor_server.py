"""Unit tests for monitor_server.py — uses a temp-dir SQLite DB."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture(autouse=True)
def tmp_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    import importlib
    import mcp_servers.monitor_server as monitor_mod
    importlib.reload(monitor_mod)
    yield monitor_mod


def test_compute_diff_no_baseline(tmp_data_dir):
    mod = tmp_data_dir
    added, removed = mod._compute_diff(None, {"items": ["22", "80"]})
    assert added == ["22", "80"]
    assert removed == []


def test_compute_diff_no_change(tmp_data_dir):
    mod = tmp_data_dir
    added, removed = mod._compute_diff({"items": ["22", "80"]}, {"items": ["22", "80"]})
    assert added == []
    assert removed == []


def test_compute_diff_added_and_removed(tmp_data_dir):
    mod = tmp_data_dir
    added, removed = mod._compute_diff({"items": ["22", "80"]}, {"items": ["22", "443"]})
    assert added == ["443"]
    assert removed == ["80"]


def test_snapshot_round_trip(tmp_data_dir):
    mod = tmp_data_dir
    assert mod._get_snapshot("task-1", "example.com", "ports") is None
    mod._save_snapshot("task-1", "owner1", "example.com", "ports", None, {"items": ["22", "80"]})
    snap = mod._get_snapshot("task-1", "example.com", "ports")
    assert snap == {"items": ["22", "80"]}


def test_save_snapshot_preserves_engagement_id_on_update(tmp_data_dir):
    mod = tmp_data_dir
    mod._save_snapshot("task-1", "owner1", "example.com", "ports", "eng-1", {"items": ["22"]})
    mod._save_snapshot("task-1", "owner1", "example.com", "ports", None, {"items": ["22", "80"]})
    conn = mod._get_db()
    row = conn.execute(
        "SELECT engagement_id FROM monitor_state WHERE task_id=? AND target=? AND check_type=?",
        ("task-1", "example.com", "ports"),
    ).fetchone()
    conn.close()
    assert row["engagement_id"] == "eng-1"


@pytest.mark.asyncio
async def test_monitor_list_tasks_and_get_state(tmp_data_dir):
    mod = tmp_data_dir
    mod._save_snapshot("task-1", "owner1", "example.com", "ports", None, {"items": ["22", "80"]})

    results = await mod.call_tool("monitor_list_tasks", {})
    assert "task-1" in results[0].text
    assert "example.com" in results[0].text

    results = await mod.call_tool("monitor_get_state", {"task_id": "task-1", "target": "example.com", "check_type": "ports"})
    assert "22" in results[0].text


@pytest.mark.asyncio
async def test_monitor_get_state_empty(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("monitor_get_state", {"task_id": "nope", "target": "x", "check_type": "ports"})
    assert "No stored snapshot" in results[0].text


@pytest.mark.asyncio
async def test_monitor_diff_history(tmp_data_dir):
    mod = tmp_data_dir
    mod._record_diff("task-1", "example.com", "ports", ["443"], ["80"])
    results = await mod.call_tool("monitor_diff_history", {"task_id": "task-1"})
    text = results[0].text
    assert "443" in text
    assert "80" in text


@pytest.mark.asyncio
async def test_monitor_reset(tmp_data_dir):
    mod = tmp_data_dir
    mod._save_snapshot("task-1", "owner1", "example.com", "ports", None, {"items": ["22"]})
    results = await mod.call_tool("monitor_reset", {"task_id": "task-1"})
    assert "Cleared 1" in results[0].text
    assert mod._get_snapshot("task-1", "example.com", "ports") is None


@pytest.mark.asyncio
async def test_module_import_survives_unwritable_data_dir(tmp_path, monkeypatch):
    """Same regression guard as asset_server.py: a broken data dir must not
    crash tool registration."""
    import importlib
    import mcp_servers.monitor_server as monitor_mod

    bogus_data_dir = tmp_path / "data"
    bogus_data_dir.write_text("not a directory")

    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(bogus_data_dir))
    importlib.reload(monitor_mod)

    assert any(t.name == "monitor_list_tasks" for t in monitor_mod.TOOLS)

    results = await monitor_mod.call_tool("monitor_list_tasks", {})
    assert "[error:" in results[0].text
