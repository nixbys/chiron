"""Unit tests for engagement_server.py — uses a temp-dir SQLite DB."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture(autouse=True)
def tmp_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    import importlib
    import mcp_servers.engagement_server as engagement_mod
    importlib.reload(engagement_mod)
    yield engagement_mod


async def _create(mod, name="acme-q3-pentest", **extra):
    results = await mod.call_tool("engagement_create", {"name": name, **extra})
    text = results[0].text
    assert "[error:" not in text
    # "Engagement 'acme-q3-pentest' created (id=<hex>)."
    return text.split("id=")[1].rstrip(").")


@pytest.mark.asyncio
async def test_create_and_list(tmp_data_dir):
    mod = tmp_data_dir
    await _create(mod)
    results = await mod.call_tool("engagement_list", {})
    assert "acme-q3-pentest" in results[0].text


@pytest.mark.asyncio
async def test_create_duplicate_name_rejected(tmp_data_dir):
    mod = tmp_data_dir
    await _create(mod)
    results = await mod.call_tool("engagement_create", {"name": "acme-q3-pentest"})
    assert "[error:duplicate]" in results[0].text


@pytest.mark.asyncio
async def test_get_returns_details(tmp_data_dir):
    mod = tmp_data_dir
    engagement_id = await _create(mod, client="Acme Corp", scope=["10.0.0.0/24"])
    results = await mod.call_tool("engagement_get", {"engagement_id": engagement_id})
    text = results[0].text
    assert "acme-q3-pentest" in text
    assert "Acme Corp" in text
    assert "10.0.0.0/24" in text


@pytest.mark.asyncio
async def test_get_unknown_id(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("engagement_get", {"engagement_id": "nope"})
    assert "[error:not_found]" in results[0].text


@pytest.mark.asyncio
async def test_update(tmp_data_dir):
    mod = tmp_data_dir
    engagement_id = await _create(mod)
    await mod.call_tool("engagement_update", {"engagement_id": engagement_id, "client": "New Client"})
    results = await mod.call_tool("engagement_get", {"engagement_id": engagement_id})
    assert "New Client" in results[0].text


# ---- Temporal scope fields (Phase I) -------------------------------------


@pytest.mark.asyncio
async def test_create_with_temporal_scope_fields(tmp_data_dir):
    mod = tmp_data_dir
    engagement_id = await _create(
        mod, authorized_hours="09:00-17:00", blackout_dates=["2026-12-25"],
    )
    results = await mod.call_tool("engagement_get", {"engagement_id": engagement_id})
    text = results[0].text
    assert "09:00-17:00" in text
    assert "2026-12-25" in text


@pytest.mark.asyncio
async def test_create_without_temporal_scope_fields_defaults_to_no_restriction(tmp_data_dir):
    mod = tmp_data_dir
    engagement_id = await _create(mod)
    results = await mod.call_tool("engagement_get", {"engagement_id": engagement_id})
    text = results[0].text
    assert "no restriction" in text
    assert "Blackout dates: (none)" in text


@pytest.mark.asyncio
async def test_update_temporal_scope_fields(tmp_data_dir):
    mod = tmp_data_dir
    engagement_id = await _create(mod)
    await mod.call_tool("engagement_update", {
        "engagement_id": engagement_id,
        "authorized_hours": "22:00-02:00",
        "blackout_dates": ["2026-01-01"],
    })
    results = await mod.call_tool("engagement_get", {"engagement_id": engagement_id})
    text = results[0].text
    assert "22:00-02:00" in text
    assert "2026-01-01" in text


@pytest.mark.asyncio
async def test_close(tmp_data_dir):
    mod = tmp_data_dir
    engagement_id = await _create(mod)
    results = await mod.call_tool("engagement_close", {"engagement_id": engagement_id})
    assert "[error:" not in results[0].text
    results = await mod.call_tool("engagement_list", {"status": "closed"})
    assert "acme-q3-pentest" in results[0].text


@pytest.mark.asyncio
async def test_close_unknown_id(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("engagement_close", {"engagement_id": "nope"})
    assert "[error:not_found]" in results[0].text


@pytest.mark.asyncio
async def test_log_event_and_timeline_ordering(tmp_data_dir):
    mod = tmp_data_dir
    engagement_id = await _create(mod)
    await mod.call_tool("engagement_log_event", {
        "engagement_id": engagement_id, "event_type": "scan_started", "summary": "kicked off nmap",
    })
    await mod.call_tool("engagement_log_event", {
        "engagement_id": engagement_id, "event_type": "scan_completed", "summary": "nmap done, 3 open ports",
    })
    results = await mod.call_tool("engagement_timeline", {"engagement_id": engagement_id})
    text = results[0].text
    assert text.index("kicked off nmap") < text.index("nmap done, 3 open ports")


@pytest.mark.asyncio
async def test_log_event_unknown_engagement(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("engagement_log_event", {
        "engagement_id": "nope", "event_type": "note", "summary": "x",
    })
    assert "[error:not_found]" in results[0].text


@pytest.mark.asyncio
async def test_timeline_empty(tmp_data_dir):
    mod = tmp_data_dir
    engagement_id = await _create(mod)
    results = await mod.call_tool("engagement_timeline", {"engagement_id": engagement_id})
    assert "No events" in results[0].text


@pytest.mark.asyncio
async def test_module_import_survives_unwritable_data_dir(tmp_path, monkeypatch):
    """Same regression guard as asset_server.py: a broken data dir must not
    crash tool registration."""
    import importlib
    import mcp_servers.engagement_server as engagement_mod

    bogus_data_dir = tmp_path / "data"
    bogus_data_dir.write_text("not a directory")

    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(bogus_data_dir))
    importlib.reload(engagement_mod)

    assert any(t.name == "engagement_create" for t in engagement_mod.TOOLS)

    results = await engagement_mod.call_tool("engagement_create", {"name": "x"})
    assert "[error:" in results[0].text


@pytest.mark.asyncio
async def test_get_timeline_helper_matches_tool_output(tmp_data_dir):
    """_get_timeline (used by the security dashboard's engagement-detail
    route) must return the same events, in the same order, as the
    engagement_timeline tool that shares its implementation."""
    mod = tmp_data_dir
    engagement_id = await _create(mod)
    await mod.call_tool("engagement_log_event", {
        "engagement_id": engagement_id, "event_type": "scan_started", "summary": "first",
    })
    await mod.call_tool("engagement_log_event", {
        "engagement_id": engagement_id, "event_type": "scan_completed", "summary": "second",
    })
    events = mod._get_timeline(engagement_id)
    assert [e["summary"] for e in events] == ["first", "second"]
    assert events[0]["event_type"] == "scan_started"


def test_get_timeline_empty(tmp_data_dir):
    mod = tmp_data_dir
    assert mod._get_timeline("no-such-engagement") == []
