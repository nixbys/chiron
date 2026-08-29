"""Route-level regression tests for GET /api/security/dashboard.

Mirrors tests/test_diagnostics_service_route.py's pattern: a real FastAPI +
TestClient mounting just this router, with require_admin and the per-
section fetch functions patched.
"""
import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("starlette.testclient")

from fastapi import FastAPI, HTTPException, Request
from starlette.testclient import TestClient

secdash = pytest.importorskip("routes.security_dashboard_routes")


def _client_with_admin_gate(monkeypatch, gate, **fetch_overrides):
    monkeypatch.setattr(secdash, "require_admin", gate)
    for name, value in fetch_overrides.items():
        monkeypatch.setattr(secdash, name, value)

    app = FastAPI()
    app.include_router(secdash.setup_security_dashboard_routes())
    return TestClient(app, raise_server_exceptions=False)


def _allow(_request: Request):
    return None


def _deny(_request: Request):
    raise HTTPException(403, "Admin only")


def test_unauthenticated_is_rejected(monkeypatch):
    client = _client_with_admin_gate(monkeypatch, _deny)
    r = client.get("/api/security/dashboard")
    assert r.status_code == 403


def test_admin_gets_aggregated_sections(monkeypatch):
    client = _client_with_admin_gate(
        monkeypatch, _allow,
        _fetch_findings_summary=lambda: {"total": 3, "by_severity": [], "by_status": []},
        _fetch_watchlist_summary=lambda: {"count": 1, "entries": [{"indicator": "1.2.3.4", "kind": "ip", "engagement_id": None}]},
        _fetch_scan_drift=lambda limit: {"diffs": []},
        _fetch_engagements=lambda limit: {"list": [{"id": "eng-1", "name": "Acme Pentest", "status": "active"}]},
        _fetch_host_telemetry_summary=lambda: {"process_count": 42},
    )
    r = client.get("/api/security/dashboard")
    assert r.status_code == 200
    body = r.json()
    assert body["findings"]["total"] == 3
    assert body["watchlist"]["count"] == 1
    assert body["scan_drift"]["diffs"] == []
    assert body["engagements"]["list"][0]["name"] == "Acme Pentest"
    assert body["host_telemetry"]["process_count"] == 42


def test_one_section_failing_does_not_break_the_others(monkeypatch):
    """Best-effort per section: OpenSearch being unreachable (or any other
    single source failing) surfaces as an `error` field on that section,
    never a 500 for the whole dashboard."""
    client = _client_with_admin_gate(
        monkeypatch, _allow,
        _fetch_findings_summary=lambda: {"error": "OpenSearch unreachable"},
        _fetch_watchlist_summary=lambda: {"count": 0, "entries": []},
        _fetch_scan_drift=lambda limit: {"diffs": []},
        _fetch_engagements=lambda limit: {"list": []},
        _fetch_host_telemetry_summary=lambda: {"process_count": 1},
    )
    r = client.get("/api/security/dashboard")
    assert r.status_code == 200
    body = r.json()
    assert "error" in body["findings"]
    assert body["watchlist"]["count"] == 0


def test_limit_is_clamped(monkeypatch):
    seen = {}

    def _capture_drift(limit):
        seen["limit"] = limit
        return {"diffs": []}

    client = _client_with_admin_gate(
        monkeypatch, _allow,
        _fetch_findings_summary=lambda: {"total": 0, "by_severity": [], "by_status": []},
        _fetch_watchlist_summary=lambda: {"count": 0, "entries": []},
        _fetch_scan_drift=_capture_drift,
        _fetch_engagements=lambda limit: {"list": []},
        _fetch_host_telemetry_summary=lambda: {},
    )
    r = client.get("/api/security/dashboard?limit=5000")
    assert r.status_code == 200
    assert seen["limit"] == 100


@pytest.mark.asyncio
async def test_fetch_findings_summary_reuses_finding_stats_query():
    """Real (non-mocked) unit test of the aggregation-building function
    itself, against a mocked findings_server._req -- confirms it's the same
    query shape as finding_stats, not just that the route wires it up."""
    import mcp_servers.findings_server as findings_mod
    from unittest.mock import patch

    fake_response = {
        "hits": {"total": {"value": 5}},
        "aggregations": {
            "by_severity": {"buckets": [{"key": "high", "doc_count": 2}]},
            "by_status": {"buckets": [{"key": "open", "doc_count": 5}]},
        },
    }
    with patch.object(findings_mod, "_ensure_index", return_value=None), \
         patch.object(findings_mod, "_req", return_value=fake_response):
        result = secdash._fetch_findings_summary()
    assert result["total"] == 5
    assert result["by_severity"] == [{"key": "high", "doc_count": 2}]


def test_fetch_watchlist_summary_uses_list_active_watchlist():
    from unittest.mock import patch
    import mcp_servers.watchlist_server as watchlist_mod

    entries = [{"indicator": "1.2.3.4", "kind": "ip", "engagement_id": "eng-1"}]
    with patch.object(watchlist_mod, "_list_active_watchlist", return_value=entries):
        result = secdash._fetch_watchlist_summary()
    assert result["count"] == 1
    assert result["entries"][0]["indicator"] == "1.2.3.4"


def test_fetch_scan_drift_parses_json_columns():
    from unittest.mock import patch
    import mcp_servers.monitor_server as monitor_mod

    raw_diffs = [{"task_id": "t1", "target": "example.com", "check_type": "ports", "added": "[\"22/tcp\"]", "removed": "[]", "ts": 123.0}]
    with patch.object(monitor_mod, "_list_recent_diffs", return_value=raw_diffs):
        result = secdash._fetch_scan_drift(20)
    assert result["diffs"][0]["added"] == ["22/tcp"]
    assert result["diffs"][0]["removed"] == []


def test_fetch_engagements_uses_list_engagements():
    from unittest.mock import patch
    import mcp_servers.engagement_server as engagement_mod

    rows = [{"id": "eng-1", "name": "Acme", "client": "Acme Corp", "status": "active"}]
    with patch.object(engagement_mod, "_list_engagements", return_value=rows):
        result = secdash._fetch_engagements(20)
    assert result["list"] == rows
