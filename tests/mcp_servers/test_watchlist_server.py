"""Unit tests for watchlist_server.py — uses a temp-dir SQLite DB."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture(autouse=True)
def tmp_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    import importlib
    import mcp_servers.common as common_mod
    import mcp_servers.watchlist_server as watchlist_mod
    # Reload common.py too, not just watchlist_server.py -- watchlist_add's
    # new check_scope_from_args() call reads common's module-level
    # _ENGAGEMENT_DB_PATH, which must point at *this* test's tmp_path, not
    # whatever another test file's own reload last left it pointing at.
    importlib.reload(common_mod)
    importlib.reload(watchlist_mod)
    yield watchlist_mod


@pytest.mark.asyncio
async def test_add_and_list_ip(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("watchlist_add", {"indicator": "203.0.113.5", "kind": "ip"})
    assert "[error:" not in results[0].text

    results = await mod.call_tool("watchlist_list", {})
    assert "203.0.113.5" in results[0].text


@pytest.mark.asyncio
async def test_add_duplicate_rejected(tmp_data_dir):
    mod = tmp_data_dir
    await mod.call_tool("watchlist_add", {"indicator": "203.0.113.5", "kind": "ip"})
    results = await mod.call_tool("watchlist_add", {"indicator": "203.0.113.5", "kind": "ip"})
    assert "[error:duplicate]" in results[0].text


@pytest.mark.asyncio
async def test_add_invalid_ip_rejected(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("watchlist_add", {"indicator": "not_an_ip!!", "kind": "ip"})
    assert "[error:" in results[0].text


@pytest.mark.asyncio
async def test_add_invalid_hash_rejected(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("watchlist_add", {"indicator": "not-a-hash", "kind": "hash"})
    assert "[error:invalid_hash]" in results[0].text


@pytest.mark.asyncio
async def test_add_valid_hash_accepted(tmp_data_dir):
    mod = tmp_data_dir
    sha256 = "a" * 64
    results = await mod.call_tool("watchlist_add", {"indicator": sha256, "kind": "hash"})
    assert "[error:" not in results[0].text


@pytest.mark.asyncio
async def test_add_valid_domain_and_url(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("watchlist_add", {"indicator": "evil.example.com", "kind": "domain"})
    assert "[error:" not in results[0].text
    results = await mod.call_tool("watchlist_add", {"indicator": "https://evil.example.com/x", "kind": "url"})
    assert "[error:" not in results[0].text


@pytest.mark.asyncio
async def test_list_filters_by_engagement(tmp_data_dir):
    mod = tmp_data_dir
    await mod.call_tool("watchlist_add", {"indicator": "203.0.113.1", "kind": "ip", "engagement_id": "eng-1"})
    await mod.call_tool("watchlist_add", {"indicator": "203.0.113.2", "kind": "ip", "engagement_id": "eng-2"})
    results = await mod.call_tool("watchlist_list", {"engagement_id": "eng-1"})
    text = results[0].text
    assert "203.0.113.1" in text
    assert "203.0.113.2" not in text


@pytest.mark.asyncio
async def test_pause_resume_and_status_filter(tmp_data_dir):
    mod = tmp_data_dir
    await mod.call_tool("watchlist_add", {"indicator": "203.0.113.9", "kind": "ip"})
    row = mod._list_active_watchlist()[0]

    await mod.call_tool("watchlist_pause", {"watchlist_id": row["id"]})
    results = await mod.call_tool("watchlist_list", {"status": "active"})
    assert "203.0.113.9" not in results[0].text
    assert mod._list_active_watchlist() == []

    await mod.call_tool("watchlist_resume", {"watchlist_id": row["id"]})
    assert len(mod._list_active_watchlist()) == 1


@pytest.mark.asyncio
async def test_remove(tmp_data_dir):
    mod = tmp_data_dir
    await mod.call_tool("watchlist_add", {"indicator": "203.0.113.10", "kind": "ip"})
    row = mod._list_active_watchlist()[0]
    results = await mod.call_tool("watchlist_remove", {"watchlist_id": row["id"]})
    assert "[error:" not in results[0].text
    assert mod._list_active_watchlist() == []


@pytest.mark.asyncio
async def test_remove_unknown_id(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("watchlist_remove", {"watchlist_id": 9999})
    assert "[error:not_found]" in results[0].text


def test_save_and_get_last_check(tmp_data_dir):
    mod = tmp_data_dir
    assert mod._get_last_check(1, "shodan") is None
    mod._save_check(1, "shodan", {"ports": [22, 80]})
    check = mod._get_last_check(1, "shodan")
    assert check is not None
    assert "22" in check["snapshot"]


@pytest.mark.asyncio
async def test_check_history_tool(tmp_data_dir):
    mod = tmp_data_dir
    await mod.call_tool("watchlist_add", {"indicator": "203.0.113.11", "kind": "ip"})
    row = mod._list_active_watchlist()[0]
    mod._save_check(row["id"], "shodan", {"ports": [22]})
    results = await mod.call_tool("watchlist_check_history", {"watchlist_id": row["id"]})
    assert "shodan" in results[0].text


@pytest.mark.asyncio
async def test_module_import_survives_unwritable_data_dir(tmp_path, monkeypatch):
    """Same regression guard as asset_server.py: a broken data dir must not
    crash tool registration."""
    import importlib
    import mcp_servers.watchlist_server as watchlist_mod

    bogus_data_dir = tmp_path / "data"
    bogus_data_dir.write_text("not a directory")

    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(bogus_data_dir))
    importlib.reload(watchlist_mod)

    assert any(t.name == "watchlist_add" for t in watchlist_mod.TOOLS)

    results = await watchlist_mod.call_tool("watchlist_add", {"indicator": "203.0.113.1", "kind": "ip"})
    assert "[error:" in results[0].text


@pytest.mark.asyncio
async def test_list_watchlist_helper_filters(tmp_data_dir):
    """_list_watchlist (used by the security dashboard's watchlist route)
    supports the same kind/engagement_id/status filters as the
    watchlist_list tool that shares its query."""
    mod = tmp_data_dir
    await mod.call_tool("watchlist_add", {"indicator": "203.0.113.5", "kind": "ip", "engagement_id": "eng-1"})
    await mod.call_tool("watchlist_add", {"indicator": "evil.example", "kind": "domain"})

    assert len(mod._list_watchlist()) == 2
    assert [e["indicator"] for e in mod._list_watchlist(kind="domain")] == ["evil.example"]
    assert [e["indicator"] for e in mod._list_watchlist(engagement_id="eng-1")] == ["203.0.113.5"]
    assert mod._list_watchlist(status="paused") == []


@pytest.mark.asyncio
async def test_list_checks_helper(tmp_data_dir):
    mod = tmp_data_dir
    await mod.call_tool("watchlist_add", {"indicator": "203.0.113.5", "kind": "ip"})
    watchlist_id = mod._list_watchlist()[0]["id"]
    assert mod._list_checks(watchlist_id) == []
    mod._save_check(watchlist_id, "shodan", {"ports": [22, 80]})
    checks = mod._list_checks(watchlist_id)
    assert len(checks) == 1
    assert checks[0]["provider"] == "shodan"
