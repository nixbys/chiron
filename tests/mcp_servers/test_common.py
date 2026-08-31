"""Unit tests for mcp_servers/common.py's local/container exec-mode branching,
audit trail, rate limiting, and engagement scope enforcement."""

import importlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp_servers import common


@pytest.fixture
def audit_env(tmp_path, monkeypatch):
    """Isolated ODYSSEUS_DATA_DIR + a reload so common.py's module-level
    _DATA_DIR/_AUDIT_DB_PATH constants (and the _audit_db_initialized flag)
    pick up the fresh path -- same pattern engagement_server.py's/
    watchlist_server.py's own tests already use."""
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("TOOLCHAIN_RATE_LIMIT_WINDOW", "60")
    monkeypatch.setenv("TOOLCHAIN_RATE_LIMIT", "20")
    monkeypatch.delenv("TOOLCHAIN_RATE_LIMIT_NMAP", raising=False)
    importlib.reload(common)
    yield common


def test_resolve_exec_mode_defaults_to_container(monkeypatch):
    monkeypatch.delenv("TOOLCHAIN_EXEC_MODE_NMAP", raising=False)
    monkeypatch.setattr(common, "_EXEC_MODE_DEFAULT", "container")
    assert common._resolve_exec_mode("nmap") == "container"


def test_resolve_exec_mode_global_override(monkeypatch):
    monkeypatch.delenv("TOOLCHAIN_EXEC_MODE_NMAP", raising=False)
    monkeypatch.setattr(common, "_EXEC_MODE_DEFAULT", "local")
    assert common._resolve_exec_mode("nmap") == "local"


def test_resolve_exec_mode_per_tool_overrides_global(monkeypatch):
    monkeypatch.setattr(common, "_EXEC_MODE_DEFAULT", "container")
    monkeypatch.setenv("TOOLCHAIN_EXEC_MODE_NMAP", "local")
    assert common._resolve_exec_mode("nmap") == "local"
    # A different binary is unaffected by nmap's override.
    monkeypatch.delenv("TOOLCHAIN_EXEC_MODE_GOBUSTER", raising=False)
    assert common._resolve_exec_mode("gobuster") == "container"


def test_exec_local_not_installed(monkeypatch):
    monkeypatch.setattr(common.shutil, "which", lambda binary: None)
    output = common._exec_local(["totally-not-a-real-binary"], timeout=5, stdin=None)
    assert "[error:not_installed]" in output


@patch("mcp_servers.common.subprocess.run")
def test_exec_local_returns_stdout(mock_run, monkeypatch):
    monkeypatch.setattr(common.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    mock_run.return_value = MagicMock(stdout="22/tcp open ssh", stderr="", returncode=0)
    output = common._exec_local(["nmap", "-sV", "127.0.0.1"], timeout=5, stdin=None)
    assert "22/tcp" in output
    assert mock_run.called


@patch("mcp_servers.common.subprocess.run")
def test_exec_local_includes_stderr(mock_run, monkeypatch):
    monkeypatch.setattr(common.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    mock_run.return_value = MagicMock(stdout="", stderr="permission denied", returncode=1)
    output = common._exec_local(["nmap"], timeout=5, stdin=None)
    assert "[stderr]" in output
    assert "permission denied" in output


@patch("mcp_servers.common.subprocess.run")
def test_exec_local_timeout(mock_run, monkeypatch):
    monkeypatch.setattr(common.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmap"], timeout=5)
    output = common._exec_local(["nmap"], timeout=5, stdin=None)
    assert "[error:timeout]" in output


@patch("mcp_servers.common._exec_local")
@patch("mcp_servers.common._exec_container")
def test_exec_in_toolchain_dispatches_to_container_by_default(mock_container, mock_local, monkeypatch):
    monkeypatch.setattr(common, "_EXEC_MODE_DEFAULT", "container")
    monkeypatch.delenv("TOOLCHAIN_EXEC_MODE_NMAP", raising=False)
    mock_container.return_value = "container output"
    result = common.exec_in_toolchain(["nmap", "127.0.0.1"])
    assert result == "container output"
    mock_container.assert_called_once()
    mock_local.assert_not_called()


@patch("mcp_servers.common._exec_local")
@patch("mcp_servers.common._exec_container")
def test_exec_in_toolchain_dispatches_to_local_when_selected(mock_container, mock_local, monkeypatch):
    monkeypatch.setattr(common, "_EXEC_MODE_DEFAULT", "container")
    monkeypatch.setenv("TOOLCHAIN_EXEC_MODE_NMAP", "local")
    mock_local.return_value = "local output"
    result = common.exec_in_toolchain(["nmap", "127.0.0.1"])
    assert result == "local output"
    mock_local.assert_called_once()
    mock_container.assert_not_called()


# ---- Audit trail ------------------------------------------------------------


def test_exec_in_toolchain_logs_successful_invocation(audit_env):
    with patch.object(audit_env, "_exec_container", return_value="22/tcp open ssh"):
        audit_env.exec_in_toolchain(["nmap", "-sV", "10.0.0.5"])
    conn = audit_env._get_audit_db()
    row = conn.execute("SELECT * FROM tool_invocations WHERE binary='nmap'").fetchone()
    conn.close()
    assert row is not None
    assert row["outcome"] == "ok"
    assert row["mode"] == "container"
    assert "10.0.0.5" in row["args"]
    assert row["duration_ms"] is not None


def test_exec_in_toolchain_logs_error_outcome(audit_env):
    with patch.object(audit_env, "_exec_container", return_value="[error:network] connection refused"):
        audit_env.exec_in_toolchain(["nikto", "-h", "10.0.0.5"])
    conn = audit_env._get_audit_db()
    row = conn.execute("SELECT * FROM tool_invocations WHERE binary='nikto'").fetchone()
    conn.close()
    assert row["outcome"] == "error"
    assert "connection refused" in row["detail"]


def test_exec_in_toolchain_logs_timeout_outcome(audit_env):
    with patch.object(audit_env, "_exec_container", return_value="[error:timeout] Command exceeded 30s"):
        audit_env.exec_in_toolchain(["sqlmap", "-u", "http://x"], timeout=30)
    conn = audit_env._get_audit_db()
    row = conn.execute("SELECT * FROM tool_invocations WHERE binary='sqlmap'").fetchone()
    conn.close()
    assert row["outcome"] == "timeout"


def test_audit_log_write_failure_does_not_break_the_call(audit_env, monkeypatch):
    """A logging bug must never break an actual scan."""
    monkeypatch.setattr(audit_env, "_get_audit_db", MagicMock(side_effect=RuntimeError("disk full")))
    with patch.object(audit_env, "_exec_container", return_value="real scan output"):
        result = audit_env.exec_in_toolchain(["nmap", "10.0.0.5"])
    assert result == "real scan output"


# ---- Rate limiting -----------------------------------------------------------
#
# TOOLCHAIN_RATE_LIMIT/_WINDOW are read once into module-level constants at
# import time (same as the pre-existing TOOLCHAIN_EXEC_MODE/_EXEC_MODE_DEFAULT
# above) -- a long-running MCP server process doesn't need to notice an env
# var changing mid-run. So these tests monkeypatch the frozen attributes
# directly instead of the env var + reload, same as
# test_resolve_exec_mode_defaults_to_container et al. already do for
# _EXEC_MODE_DEFAULT. Only the per-binary override
# (TOOLCHAIN_RATE_LIMIT_<BINARY>) is read fresh on every call, since that's
# meant as a targeted, no-restart-needed dial -- see _rate_limit_for.


def test_rate_limit_blocks_after_threshold(audit_env, monkeypatch):
    monkeypatch.setattr(audit_env, "_RATE_LIMIT_DEFAULT", 2)
    with patch.object(audit_env, "_exec_container", return_value="ok") as mock_exec:
        assert "[error:" not in audit_env.exec_in_toolchain(["nmap", "10.0.0.5"])
        assert "[error:" not in audit_env.exec_in_toolchain(["nmap", "10.0.0.6"])
        third = audit_env.exec_in_toolchain(["nmap", "10.0.0.7"])
    assert "[error:rate_limited]" in third
    assert mock_exec.call_count == 2  # the third call never reached the real exec


def test_rate_limit_is_per_binary(audit_env, monkeypatch):
    monkeypatch.setattr(audit_env, "_RATE_LIMIT_DEFAULT", 1)
    with patch.object(audit_env, "_exec_container", return_value="ok"):
        assert "[error:" not in audit_env.exec_in_toolchain(["nmap", "10.0.0.5"])
        # A different binary has its own independent budget.
        assert "[error:" not in audit_env.exec_in_toolchain(["whois", "example.com"])
        assert "[error:rate_limited]" in audit_env.exec_in_toolchain(["nmap", "10.0.0.6"])


def test_rate_limit_per_binary_override(audit_env, monkeypatch):
    monkeypatch.setattr(audit_env, "_RATE_LIMIT_DEFAULT", 20)
    monkeypatch.setenv("TOOLCHAIN_RATE_LIMIT_NMAP", "1")
    with patch.object(audit_env, "_exec_container", return_value="ok"):
        assert "[error:" not in audit_env.exec_in_toolchain(["nmap", "10.0.0.5"])
        assert "[error:rate_limited]" in audit_env.exec_in_toolchain(["nmap", "10.0.0.6"])


def test_rate_limit_disabled_when_window_zero(audit_env, monkeypatch):
    monkeypatch.setattr(audit_env, "_RATE_LIMIT_WINDOW_S", 0)
    monkeypatch.setattr(audit_env, "_RATE_LIMIT_DEFAULT", 1)
    with patch.object(audit_env, "_exec_container", return_value="ok"):
        for _ in range(5):
            assert "[error:" not in audit_env.exec_in_toolchain(["nmap", "10.0.0.5"])


def test_rate_limited_call_is_itself_logged(audit_env, monkeypatch):
    monkeypatch.setattr(audit_env, "_RATE_LIMIT_DEFAULT", 1)
    with patch.object(audit_env, "_exec_container", return_value="ok"):
        audit_env.exec_in_toolchain(["nmap", "10.0.0.5"])
        audit_env.exec_in_toolchain(["nmap", "10.0.0.6"])
    conn = audit_env._get_audit_db()
    rows = conn.execute("SELECT outcome FROM tool_invocations WHERE binary='nmap' ORDER BY id").fetchall()
    conn.close()
    assert [r["outcome"] for r in rows] == ["ok", "rate_limited"]


def test_rate_limit_check_fails_open_on_db_error(audit_env, monkeypatch):
    monkeypatch.setattr(audit_env, "_RATE_LIMIT_DEFAULT", 1)
    monkeypatch.setattr(audit_env, "_get_audit_db", MagicMock(side_effect=RuntimeError("disk full")))
    with patch.object(audit_env, "_exec_container", return_value="ok"):
        result = audit_env.exec_in_toolchain(["nmap", "10.0.0.5"])
    assert result == "ok"


# ---- Engagement scope enforcement --------------------------------------------
#
# check_scope() reads engagement_server.py's own engagements.db directly
# (see that module's docstring on the "no cross-import between MCP servers"
# pattern) -- these tests seed a minimal engagements table by hand rather
# than importing engagement_server, matching that same isolation.


def _seed_engagement(data_dir, engagement_id, scope=None, out_of_scope=None):
    conn = sqlite3.connect(str(Path(data_dir) / "engagements.db"))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS engagements (id TEXT PRIMARY KEY, scope TEXT, out_of_scope TEXT)"
    )
    conn.execute(
        "INSERT INTO engagements (id, scope, out_of_scope) VALUES (?, ?, ?)",
        (engagement_id, json.dumps(scope or []), json.dumps(out_of_scope or [])),
    )
    conn.commit()
    conn.close()


def test_target_matches_exact_string():
    assert common._target_matches("10.0.0.5", ["10.0.0.5"])
    assert not common._target_matches("10.0.0.6", ["10.0.0.5"])


def test_target_matches_cidr_containment():
    assert common._target_matches("10.0.0.5", ["10.0.0.0/24"])
    assert not common._target_matches("10.0.1.5", ["10.0.0.0/24"])


def test_target_matches_domain_suffix():
    assert common._target_matches("api.example.com", ["example.com"])
    assert not common._target_matches("evilexample.com", ["example.com"])


def test_check_scope_no_engagement_id_is_unenforced(audit_env):
    """Back-compat: every call site that predates this feature keeps working."""
    assert audit_env.check_scope(None, "8.8.8.8", "nmap_scan") is None


def test_check_scope_unknown_engagement_is_unenforced(audit_env):
    assert audit_env.check_scope("does-not-exist", "8.8.8.8", "nmap_scan") is None


def test_check_scope_in_scope_target_passes(audit_env, tmp_path):
    _seed_engagement(tmp_path, "eng-1", scope=["10.0.0.0/24"])
    assert audit_env.check_scope("eng-1", "10.0.0.5", "nmap_scan") is None


def test_check_scope_target_outside_declared_scope_blocks(audit_env, tmp_path):
    _seed_engagement(tmp_path, "eng-1", scope=["10.0.0.0/24"])
    result = audit_env.check_scope("eng-1", "8.8.8.8", "nmap_scan")
    assert result is not None
    assert "[error:out_of_scope]" in result


def test_check_scope_explicit_out_of_scope_blocks_with_no_positive_scope(audit_env, tmp_path):
    _seed_engagement(tmp_path, "eng-1", scope=[], out_of_scope=["10.0.0.9"])
    result = audit_env.check_scope("eng-1", "10.0.0.9", "nmap_scan")
    assert result is not None
    assert "[error:out_of_scope]" in result


def test_check_scope_no_scope_declared_allows_anything_not_excluded(audit_env, tmp_path):
    _seed_engagement(tmp_path, "eng-1", scope=[])
    assert audit_env.check_scope("eng-1", "8.8.8.8", "nmap_scan") is None


def test_check_scope_block_is_audit_logged(audit_env, tmp_path):
    _seed_engagement(tmp_path, "eng-1", scope=["10.0.0.0/24"])
    audit_env.check_scope("eng-1", "8.8.8.8", "nmap_scan")
    conn = audit_env._get_audit_db()
    row = conn.execute("SELECT * FROM tool_invocations WHERE outcome='blocked_out_of_scope'").fetchone()
    conn.close()
    assert row is not None
    assert row["engagement_id"] == "eng-1"
    assert "8.8.8.8" in row["args"]


def test_check_scope_override_bypasses_block_and_is_flagged_not_silent(audit_env, tmp_path):
    _seed_engagement(tmp_path, "eng-1", scope=["10.0.0.0/24"])
    result = audit_env.check_scope(
        "eng-1", "8.8.8.8", "nmap_scan", override=True, override_reason="client approved expansion"
    )
    assert result is None
    conn = audit_env._get_audit_db()
    row = conn.execute("SELECT * FROM tool_invocations WHERE outcome='scope_override'").fetchone()
    conn.close()
    assert row is not None
    assert row["engagement_id"] == "eng-1"
    assert "client approved expansion" in row["detail"]


def test_check_scope_fails_open_on_db_error(audit_env, monkeypatch):
    monkeypatch.setattr(audit_env, "_get_engagement_db", MagicMock(side_effect=RuntimeError("disk full")))
    assert audit_env.check_scope("eng-1", "8.8.8.8", "nmap_scan") is None


def test_check_scope_from_args_reads_the_three_standard_args(audit_env, tmp_path):
    _seed_engagement(tmp_path, "eng-1", scope=["10.0.0.0/24"])
    blocked = audit_env.check_scope_from_args({"engagement_id": "eng-1"}, "8.8.8.8", "nmap_scan")
    assert blocked is not None and "[error:out_of_scope]" in blocked

    overridden = audit_env.check_scope_from_args(
        {"engagement_id": "eng-1", "override_scope": True, "override_reason": "test"},
        "8.8.8.8",
        "nmap_scan",
    )
    assert overridden is None


def test_exec_in_toolchain_tags_engagement_id_on_every_invocation(audit_env):
    """Not just scope violations -- every audit row is filterable by
    project, per Phase A's design (see exec_in_toolchain's docstring)."""
    with patch.object(audit_env, "_exec_container", return_value="ok"):
        audit_env.exec_in_toolchain(["nmap", "10.0.0.5"], engagement_id="eng-1")
    conn = audit_env._get_audit_db()
    row = conn.execute("SELECT * FROM tool_invocations WHERE binary='nmap'").fetchone()
    conn.close()
    assert row["engagement_id"] == "eng-1"
