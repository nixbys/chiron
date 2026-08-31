"""Unit tests for audit_server.py — uses a temp-dir SQLite DB. Writes are
seeded directly via mcp_servers.common's own writer (_log_invocation),
matching how the real audit.db is actually populated (by common.py's
exec_in_toolchain, not by this server) rather than hand-crafting rows."""

import importlib
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture(autouse=True)
def tmp_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    import mcp_servers.common as common_mod
    import mcp_servers.audit_server as audit_mod
    importlib.reload(common_mod)
    importlib.reload(audit_mod)
    yield audit_mod, common_mod


def _seed(common_mod, binary="nmap", outcome="ok", ts=None, duration_ms=100, args=None, engagement_id=None):
    conn = common_mod._get_audit_db()
    try:
        conn.execute(
            "INSERT INTO tool_invocations (ts, binary, args, mode, duration_ms, outcome, detail, engagement_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ts if ts is not None else time.time(), binary, str(args or [binary, "127.0.0.1"]), "container", duration_ms, outcome, "", engagement_id),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_audit_list_empty(tmp_data_dir):
    mod, _ = tmp_data_dir
    results = await mod.call_tool("audit_list", {})
    assert "No invocations recorded yet." in results[0].text


@pytest.mark.asyncio
async def test_audit_list_shows_seeded_invocation(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    _seed(common_mod, binary="nmap")
    results = await mod.call_tool("audit_list", {})
    assert "nmap" in results[0].text
    assert "ok" in results[0].text


@pytest.mark.asyncio
async def test_audit_list_filters_by_binary(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    _seed(common_mod, binary="nmap")
    _seed(common_mod, binary="sqlmap")
    results = await mod.call_tool("audit_list", {"binary": "sqlmap"})
    text = results[0].text
    assert "sqlmap" in text
    assert "nmap" not in text


@pytest.mark.asyncio
async def test_audit_list_filters_by_outcome(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    _seed(common_mod, binary="nmap", outcome="ok")
    _seed(common_mod, binary="nmap", outcome="rate_limited")
    results = await mod.call_tool("audit_list", {"outcome": "rate_limited"})
    text = results[0].text
    assert "rate_limited" in text
    assert text.count("rate_limited") == 1  # the header row doesn't say it, only the one matching data row
    assert "  ok  " not in text


@pytest.mark.asyncio
async def test_audit_stats_empty(tmp_data_dir):
    mod, _ = tmp_data_dir
    results = await mod.call_tool("audit_stats", {})
    assert "No invocations recorded" in results[0].text


@pytest.mark.asyncio
async def test_audit_stats_aggregates_by_binary_and_outcome(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    _seed(common_mod, binary="nmap", outcome="ok")
    _seed(common_mod, binary="nmap", outcome="ok")
    _seed(common_mod, binary="sqlmap", outcome="error")
    results = await mod.call_tool("audit_stats", {})
    text = results[0].text
    assert "Total: 3" in text
    assert "nmap=2" in text
    assert "sqlmap=1" in text
    assert "ok=2" in text
    assert "error=1" in text


@pytest.mark.asyncio
async def test_audit_stats_respects_window(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    _seed(common_mod, binary="nmap", ts=time.time() - 7200)  # 2h ago
    results = await mod.call_tool("audit_stats", {"window_hours": 1})
    assert "No invocations recorded" in results[0].text


@pytest.mark.asyncio
async def test_unknown_tool_returns_error(tmp_data_dir):
    mod, _ = tmp_data_dir
    results = await mod.call_tool("no_such_tool", {})
    assert "[error:" in results[0].text


def test_list_invocations_helper_parses_args_json(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap", ["nmap", "-sV", "10.0.0.5"], "container", 250, "ok")
    rows = mod._list_invocations()
    assert rows[0]["args"] == ["nmap", "-sV", "10.0.0.5"]
    assert rows[0]["binary"] == "nmap"


def test_list_invocations_helper_filters(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap", ["nmap"], "container", 1, "ok")
    common_mod._log_invocation("sqlmap", ["sqlmap"], "container", 1, "error")
    assert len(mod._list_invocations(binary="sqlmap")) == 1
    assert len(mod._list_invocations(outcome="error")) == 1
    assert len(mod._list_invocations()) == 2


def test_stats_helper(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap", ["nmap"], "container", 1, "ok")
    common_mod._log_invocation("nmap", ["nmap"], "container", 1, "rate_limited")
    stats = mod._stats()
    assert stats["total"] == 2
    assert {"binary": "nmap", "n": 2} in stats["by_binary"]


@pytest.mark.asyncio
async def test_module_import_survives_unwritable_data_dir(tmp_path, monkeypatch):
    """Same regression guard as asset_server.py: a broken data dir must not
    crash tool registration."""
    import mcp_servers.audit_server as audit_mod

    bogus_data_dir = tmp_path / "data"
    bogus_data_dir.write_text("not a directory")

    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(bogus_data_dir))
    importlib.reload(audit_mod)

    assert any(t.name == "audit_list" for t in audit_mod.TOOLS)

    results = await audit_mod.call_tool("audit_list", {})
    assert "[error:" in results[0].text


# ---- Engagement scope enforcement (Phase A) ---------------------------------


@pytest.mark.asyncio
async def test_audit_list_shows_scope_outcomes(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    _seed(common_mod, binary="nmap_scan", outcome="blocked_out_of_scope", engagement_id="eng-1")
    _seed(common_mod, binary="nmap_scan", outcome="scope_override", engagement_id="eng-1")
    results = await mod.call_tool("audit_list", {})
    text = results[0].text
    assert "blocked_out_of_scope" in text
    assert "scope_override" in text
    assert "eng-1" in text


@pytest.mark.asyncio
async def test_audit_list_filters_by_outcome_scope_override(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    _seed(common_mod, binary="nmap_scan", outcome="ok")
    _seed(common_mod, binary="nmap_scan", outcome="scope_override", engagement_id="eng-1")
    results = await mod.call_tool("audit_list", {"outcome": "scope_override"})
    text = results[0].text
    assert "scope_override" in text
    assert len(text.splitlines()) == 3  # header + separator + exactly one data row


@pytest.mark.asyncio
async def test_audit_list_filters_by_engagement_id(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    _seed(common_mod, binary="nmap_scan", engagement_id="eng-1")
    _seed(common_mod, binary="sqlmap_scan", engagement_id="eng-2")
    _seed(common_mod, binary="nikto_scan")  # unscoped
    results = await mod.call_tool("audit_list", {"engagement_id": "eng-1"})
    text = results[0].text
    assert "nmap_scan" in text
    assert "sqlmap_scan" not in text
    assert "nikto_scan" not in text


def test_list_invocations_helper_filters_by_engagement_id(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap", ["nmap"], "container", 1, "ok", engagement_id="eng-1")
    common_mod._log_invocation("nmap", ["nmap"], "container", 1, "ok", engagement_id="eng-2")
    common_mod._log_invocation("nmap", ["nmap"], "container", 1, "ok")
    assert len(mod._list_invocations(engagement_id="eng-1")) == 1
    assert len(mod._list_invocations()) == 3


def test_new_scope_outcomes_are_in_outcomes_tuple(tmp_data_dir):
    mod, _ = tmp_data_dir
    assert "blocked_out_of_scope" in mod._OUTCOMES
    assert "scope_override" in mod._OUTCOMES


# ---- Scope-violation checkpoint + query (Phase F) ---------------------


def test_get_checkpoint_defaults_to_zero_for_unknown_task(tmp_data_dir):
    mod, _ = tmp_data_dir
    assert mod._get_checkpoint("task-1") == 0


def test_save_and_get_checkpoint_roundtrips(tmp_data_dir):
    mod, _ = tmp_data_dir
    mod._save_checkpoint("task-1", 42)
    assert mod._get_checkpoint("task-1") == 42


def test_save_checkpoint_upserts_on_repeat_calls(tmp_data_dir):
    mod, _ = tmp_data_dir
    mod._save_checkpoint("task-1", 10)
    mod._save_checkpoint("task-1", 20)
    assert mod._get_checkpoint("task-1") == 20


def test_checkpoints_are_independent_per_task(tmp_data_dir):
    mod, _ = tmp_data_dir
    mod._save_checkpoint("task-1", 10)
    mod._save_checkpoint("task-2", 99)
    assert mod._get_checkpoint("task-1") == 10
    assert mod._get_checkpoint("task-2") == 99


def test_list_scope_violations_since_only_returns_scope_outcomes(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["10.0.0.5"], "n/a", None, "ok", engagement_id="eng-1")
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "scope_override", "approved", engagement_id="eng-1")
    rows = mod._list_scope_violations_since(0)
    assert [r["outcome"] for r in rows] == ["blocked_out_of_scope", "scope_override"]


def test_list_scope_violations_since_respects_after_id(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    first_id = mod._list_scope_violations_since(0)[0]["id"]
    common_mod._log_invocation("nmap_scan", ["9.9.9.9"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    rows = mod._list_scope_violations_since(first_id)
    assert len(rows) == 1
    assert rows[0]["args"] == ["9.9.9.9"]


def test_list_scope_violations_since_filters_by_engagement(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    common_mod._log_invocation("nmap_scan", ["9.9.9.9"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-2")
    rows = mod._list_scope_violations_since(0, engagement_id="eng-1")
    assert len(rows) == 1
    assert rows[0]["engagement_id"] == "eng-1"


# ---- Escalation windowed count (Phase J) ---------------------------------


def test_count_scope_violations_in_window_counts_matching_rows(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    common_mod._log_invocation("nmap_scan", ["9.9.9.9"], "n/a", None, "scope_override", engagement_id="eng-1")
    common_mod._log_invocation("nmap_scan", ["10.0.0.5"], "n/a", None, "ok", engagement_id="eng-1")
    assert mod._count_scope_violations_in_window("eng-1", 86400) == 2


def test_count_scope_violations_in_window_is_per_engagement(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    common_mod._log_invocation("nmap_scan", ["8.8.8.8"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-1")
    common_mod._log_invocation("nmap_scan", ["9.9.9.9"], "n/a", None, "blocked_out_of_scope", engagement_id="eng-2")
    assert mod._count_scope_violations_in_window("eng-1", 86400) == 1
    assert mod._count_scope_violations_in_window("eng-2", 86400) == 1


def test_count_scope_violations_in_window_excludes_old_rows(tmp_data_dir):
    mod, common_mod = tmp_data_dir
    _seed(common_mod, binary="nmap_scan", outcome="blocked_out_of_scope",
          ts=time.time() - 7200, engagement_id="eng-1")
    assert mod._count_scope_violations_in_window("eng-1", 3600) == 0
    assert mod._count_scope_violations_in_window("eng-1", 14400) == 1


def test_concurrent_first_access_does_not_deadlock(tmp_data_dir):
    """Regression: routes/security_dashboard_routes.py's Audit Log tab used
    to call _list_invocations and _stats concurrently via asyncio.gather.
    On the very first request against a brand-new audit.db, both threads
    raced through _get_db()'s one-time CREATE TABLE/CREATE INDEX setup and
    hit a real "database is locked" 500 in the live app -- the route now
    calls them sequentially instead, but this guards the underlying
    _get_db() against the same race directly, in case something else ever
    calls it concurrently on a fresh file again."""
    import threading

    mod, _ = tmp_data_dir
    errors = []

    def _touch():
        try:
            conn = mod._get_db()
            conn.execute("SELECT COUNT(*) FROM tool_invocations")
            conn.close()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_touch) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert not errors, f"concurrent _get_db() calls raised: {errors}"
