"""Unit tests for routes/export_routes.py's _wipe_engagement_data() /
_wipe_all_data() -- the actual multi-store deletion logic behind the
DELETE /api/security/export/* routes (see tests/test_export_routes.py
for the route-level, mocked-deep tests).

Seeds real rows into isolated per-server SQLite DBs (same ODYSSEUS_DATA_DIR
env var + module-reload pattern every other mcp_servers/*.py test file
already uses), mocks only the OpenSearch (findings_server) calls since
those need a real cluster this test suite doesn't have."""

import importlib
import time
from contextlib import contextmanager
from unittest.mock import patch

import pytest

export_routes = pytest.importorskip("routes.export_routes")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    import mcp_servers.asset_server as asset_mod
    import mcp_servers.audit_server as audit_mod
    import mcp_servers.common as common_mod
    import mcp_servers.engagement_server as engagement_mod
    import mcp_servers.watchlist_server as watchlist_mod

    for mod in (common_mod, audit_mod, asset_mod, watchlist_mod, engagement_mod):
        importlib.reload(mod)

    return {
        "common": common_mod, "audit": audit_mod, "asset": asset_mod,
        "watchlist": watchlist_mod, "engagement": engagement_mod, "tmp_path": tmp_path,
    }


def _seed_engagement(env, eid="eng-1"):
    conn = env["engagement"]._get_db()
    now = time.time()
    conn.execute(
        "INSERT INTO engagements (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)",
        (eid, f"Engagement {eid}", now, now),
    )
    conn.execute(
        "INSERT INTO engagement_events (engagement_id, event_type, summary, ts) VALUES (?, 'note', 'x', ?)",
        (eid, now),
    )
    conn.commit()
    conn.close()


def _seed_asset(env, eid="eng-1", ip="10.0.0.1"):
    conn = env["asset"]._get_db()
    now = time.time()
    conn.execute(
        "INSERT INTO assets (ip, engagement_id, first_seen, last_seen) VALUES (?, ?, ?, ?)",
        (ip, eid, now, now),
    )
    asset_id = conn.execute("SELECT id FROM assets WHERE ip=?", (ip,)).fetchone()[0]
    conn.execute(
        "INSERT INTO services (asset_id, port, protocol, first_seen, last_seen) VALUES (?, 22, 'tcp', ?, ?)",
        (asset_id, now, now),
    )
    conn.execute(
        "INSERT INTO findings (title, severity, engagement_id, first_seen, last_seen) "
        "VALUES ('Open SSH', 'low', ?, ?, ?)",
        (eid, now, now),
    )
    conn.commit()
    conn.close()


def _seed_audit(env, eid="eng-1"):
    log_path = env["common"]._write_raw_log("nmap", "full nmap output here")
    conn = env["common"]._get_audit_db()
    conn.execute(
        "INSERT INTO tool_invocations (ts, binary, args, mode, duration_ms, outcome, engagement_id, raw_log_path) "
        "VALUES (?, 'nmap', '[]', 'container', 100, 'ok', ?, ?)",
        (time.time(), eid, log_path),
    )
    conn.commit()
    conn.close()
    return log_path


def _seed_watchlist(env, eid="eng-1"):
    conn = env["watchlist"]._get_db()
    conn.execute(
        "INSERT INTO watchlist (indicator, kind, engagement_id, created_at) VALUES ('10.0.0.1', 'ip', ?, ?)",
        (eid, time.time()),
    )
    wl_id = conn.execute("SELECT id FROM watchlist WHERE indicator='10.0.0.1'").fetchone()[0]
    conn.execute(
        "INSERT INTO watchlist_checks (watchlist_id, provider, snapshot_hash, snapshot, checked_at) "
        "VALUES (?, 'shodan', 'h', '{}', ?)",
        (wl_id, time.time()),
    )
    conn.commit()
    conn.close()


@contextmanager
def _patched_findings_req(fn):
    """Patch the *real* mcp_servers.findings_server._req in place, rather
    than substituting a fake module via sys.modules -- when another test
    file in the same run has already done `import mcp_servers.
    findings_server as findings_mod` at its own module level (as
    test_export_routes.py does), the `mcp_servers` package object already
    carries a cached `.findings_server` attribute pointing at the real
    module; `import mcp_servers.findings_server` inside
    _wipe_engagement_data() resolves through that cached attribute rather
    than re-checking sys.modules, so a sys.modules-only substitution is
    silently bypassed and the real (network-calling) module wins. Patching
    the real module's own attribute in place has no such gap."""
    import mcp_servers.findings_server as real_findings_mod
    with patch.object(real_findings_mod, "_req", fn):
        yield


def _delete_by_query_stub(method, path, body=None):
    return {"deleted": 2}


# ---- _wipe_engagement_data ---------------------------------------------


def test_wipe_engagement_data_deletes_everything_scoped_to_it(env):
    _seed_engagement(env, "eng-1")
    _seed_engagement(env, "eng-2")  # must survive
    _seed_asset(env, "eng-1")
    log_path = _seed_audit(env, "eng-1")
    _seed_watchlist(env, "eng-1")

    with _patched_findings_req(_delete_by_query_stub):
        counts = export_routes._wipe_engagement_data("eng-1")

    assert counts["findings"] == 2
    assert counts["assets"] == 1
    assert counts["services"] == 1
    assert counts["local_findings"] == 1
    assert counts["audit_invocations"] == 1
    assert counts["watchlist_entries"] == 1
    assert counts["timeline_events"] == 1
    assert counts["engagements"] == 1

    # Scoped -- the other engagement is untouched.
    conn = env["engagement"]._get_db()
    remaining = conn.execute("SELECT id FROM engagements").fetchall()
    conn.close()
    assert [r[0] for r in remaining] == ["eng-2"]

    # Raw log file actually deleted from disk, not just the DB row.
    assert not (env["common"]._DATA_DIR / log_path).exists()

    # Child rows (services, watchlist_checks) really gone, not orphaned.
    conn = env["asset"]._get_db()
    assert conn.execute("SELECT COUNT(*) FROM services").fetchone()[0] == 0
    conn.close()
    conn = env["watchlist"]._get_db()
    assert conn.execute("SELECT COUNT(*) FROM watchlist_checks").fetchone()[0] == 0
    conn.close()


def test_wipe_engagement_data_one_store_failing_does_not_block_others(env):
    """Best-effort per store -- e.g. OpenSearch unreachable must not stop
    the SQLite-backed stores from being wiped."""
    _seed_engagement(env, "eng-1")
    _seed_asset(env, "eng-1")

    def _boom(*a, **k):
        raise ConnectionError("opensearch unreachable")

    with _patched_findings_req(_boom):
        counts = export_routes._wipe_engagement_data("eng-1")

    assert "findings" not in counts  # that store's failure is swallowed
    assert counts["assets"] == 1  # everything else still ran


def test_wipe_engagement_data_empty_engagement_returns_zero_counts(env):
    _seed_engagement(env, "eng-empty")
    with _patched_findings_req(_delete_by_query_stub):
        counts = export_routes._wipe_engagement_data("eng-empty")
    assert counts["assets"] == 0
    assert counts["audit_invocations"] == 0
    assert counts["engagements"] == 1  # the (now-empty) engagement itself is still removed


# ---- _wipe_all_data ------------------------------------------------------


def test_wipe_all_data_deletes_across_every_engagement(env):
    _seed_engagement(env, "eng-1")
    _seed_engagement(env, "eng-2")
    _seed_asset(env, "eng-1", ip="10.0.0.1")
    _seed_asset(env, "eng-2", ip="10.0.0.2")
    _seed_audit(env, "eng-1")
    _seed_watchlist(env, "eng-2")

    with _patched_findings_req(_delete_by_query_stub):
        counts = export_routes._wipe_all_data()

    assert counts["engagements"] == 2
    assert counts["assets"] == 2
    assert counts["audit_invocations"] == 1
    assert counts["watchlist_entries"] == 1

    conn = env["engagement"]._get_db()
    assert conn.execute("SELECT COUNT(*) FROM engagements").fetchone()[0] == 0
    conn.close()
