"""Tests for the readiness / integrity self-check (src/readiness.py)."""

from src.readiness import check_readiness


def test_readiness_reports_core_subsystems():
    result = check_readiness()

    assert {"ready", "version", "checks", "timestamp"}.issubset(result.keys())
    checks = result["checks"]
    for name in ("database", "data_dir", "local_first", "mcp_servers"):
        assert name in checks, f"missing check: {name}"

    # In the dev/test environment the local SQLite DB and data dir are present,
    # so the critical checks must pass and overall readiness must be True.
    assert checks["database"]["ok"] is True, checks["database"]
    assert checks["data_dir"]["ok"] is True, checks["data_dir"]
    assert result["ready"] is True, result


def test_local_first_check_is_informational_never_fatal():
    result = check_readiness()
    lf = result["checks"]["local_first"]
    # local_first reports whether storage stays on-host but must never gate
    # readiness — a remote database is a valid deployment.
    assert lf["ok"] is True
    assert "local" in lf


def test_mcp_servers_check_is_informational_and_reports_failures(monkeypatch):
    """A misconfigured/unreachable MCP server must be visible here (so it
    doesn't just silently disappear from the tool list, per this fork's
    release-plan reliability item), but must never fail overall readiness --
    an optional MCP server being down doesn't mean the instance is broken."""
    class _FakeManager:
        def get_all_statuses(self):
            return {
                "srv-good": {"name": "good", "status": "connected"},
                "srv-bad": {"name": "bad", "status": "error", "error": "boom"},
                "srv-slow": {"name": "slow", "status": "timeout", "error": "Timed out after 20 seconds"},
            }

    monkeypatch.setattr("src.tool_utils.get_mcp_manager", lambda: _FakeManager())

    result = check_readiness()
    mcp = result["checks"]["mcp_servers"]

    assert mcp["ok"] is True
    assert result["ready"] is True
    assert mcp["configured"] == 3
    assert mcp["connected"] == 1
    assert set(mcp["failed"]) == {"srv-bad", "srv-slow"}
    assert mcp["failed"]["srv-bad"]["error"] == "boom"


def test_mcp_servers_check_survives_missing_manager(monkeypatch):
    """No MCP manager initialized yet (e.g. readiness probed very early in
    startup) must not make the whole readiness check blow up."""
    monkeypatch.setattr("src.tool_utils.get_mcp_manager", lambda: None)

    result = check_readiness()
    mcp = result["checks"]["mcp_servers"]

    assert mcp["ok"] is True
    assert result["ready"] is True
