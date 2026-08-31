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


# ---- Security Hub management sub-panels (Phase 2.4) -----------------------


def _hub_client(monkeypatch):
    """A real app mounting the full router, admin gate always allowed."""
    monkeypatch.setattr(secdash, "require_admin", _allow)
    app = FastAPI()
    app.include_router(secdash.setup_security_dashboard_routes())
    return TestClient(app, raise_server_exceptions=False)


def test_hub_routes_reject_unauthenticated(monkeypatch):
    monkeypatch.setattr(secdash, "require_admin", _deny)
    app = FastAPI()
    app.include_router(secdash.setup_security_dashboard_routes())
    client = TestClient(app, raise_server_exceptions=False)
    # POST bodies are valid (not empty) so the 403 reflects the admin gate
    # itself, not incidental Pydantic body validation running first.
    cases = [
        ("GET", "/api/security/engagements", None),
        ("GET", "/api/security/engagements/eng-1", None),
        ("POST", "/api/security/engagements", {"name": "x"}),
        ("GET", "/api/security/watchlist", None),
        ("POST", "/api/security/watchlist", {"indicator": "1.2.3.4", "kind": "ip"}),
        ("DELETE", "/api/security/watchlist/1", None),
        ("GET", "/api/security/rules/sigma", None),
        ("GET", "/api/security/rules/yara", None),
    ]
    for method, path, body in cases:
        r = client.request(method, path, json=body)
        assert r.status_code == 403, f"{method} {path} should require admin"


def test_list_engagements_route(monkeypatch):
    import mcp_servers.engagement_server as engagement_mod
    rows = [{"id": "eng-1", "name": "Acme", "client": "Acme Corp", "status": "active"}]
    monkeypatch.setattr(engagement_mod, "_list_engagements", lambda status, limit: rows)
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/engagements")
    assert r.status_code == 200
    assert r.json()["list"] == rows


def test_get_engagement_route_not_found(monkeypatch):
    import mcp_servers.engagement_server as engagement_mod
    monkeypatch.setattr(engagement_mod, "_get_engagement", lambda eid: None)
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/engagements/nope")
    assert r.status_code == 404


def test_get_engagement_route_parses_json_fields(monkeypatch):
    import mcp_servers.engagement_server as engagement_mod
    row = {
        "id": "eng-1", "name": "Acme", "scope": '["10.0.0.0/24"]',
        "out_of_scope": "[]", "tags": '["q3"]',
    }
    monkeypatch.setattr(engagement_mod, "_get_engagement", lambda eid: dict(row))
    monkeypatch.setattr(engagement_mod, "_get_timeline", lambda eid, limit: [{"event_type": "note", "summary": "hi"}])
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/engagements/eng-1")
    assert r.status_code == 200
    body = r.json()
    assert body["engagement"]["scope"] == ["10.0.0.0/24"]
    assert body["timeline"][0]["summary"] == "hi"


def test_get_engagement_route_parses_blackout_dates(monkeypatch):
    import mcp_servers.engagement_server as engagement_mod
    row = {
        "id": "eng-1", "name": "Acme", "scope": "[]", "out_of_scope": "[]", "tags": "[]",
        "authorized_hours": "09:00-17:00", "blackout_dates": '["2026-12-25"]',
    }
    monkeypatch.setattr(engagement_mod, "_get_engagement", lambda eid: dict(row))
    monkeypatch.setattr(engagement_mod, "_get_timeline", lambda eid, limit: [])
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/engagements/eng-1")
    assert r.status_code == 200
    body = r.json()
    assert body["engagement"]["blackout_dates"] == ["2026-12-25"]
    assert body["engagement"]["authorized_hours"] == "09:00-17:00"


@pytest.mark.asyncio
async def test_create_engagement_route_returns_id(monkeypatch):
    import mcp_servers.engagement_server as engagement_mod

    async def fake_call_tool(name, arguments):
        from mcp.types import TextContent
        assert name == "engagement_create"
        assert arguments["name"] == "acme-q3"
        return [TextContent(type="text", text="Engagement 'acme-q3' created (id=abc123).")]

    monkeypatch.setattr(engagement_mod, "call_tool", fake_call_tool)
    client = _hub_client(monkeypatch)
    r = client.post("/api/security/engagements", json={"name": "acme-q3"})
    assert r.status_code == 201
    assert r.json()["engagement_id"] == "abc123"


@pytest.mark.asyncio
async def test_create_engagement_route_maps_duplicate_to_409(monkeypatch):
    import mcp_servers.engagement_server as engagement_mod

    async def fake_call_tool(name, arguments):
        from mcp.types import TextContent
        return [TextContent(type="text", text="[error:duplicate] already exists.")]

    monkeypatch.setattr(engagement_mod, "call_tool", fake_call_tool)
    client = _hub_client(monkeypatch)
    r = client.post("/api/security/engagements", json={"name": "acme-q3"})
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_close_engagement_route_maps_not_found_to_404(monkeypatch):
    import mcp_servers.engagement_server as engagement_mod

    async def fake_call_tool(name, arguments):
        from mcp.types import TextContent
        return [TextContent(type="text", text="[error:not_found] No engagement with id 'nope'")]

    monkeypatch.setattr(engagement_mod, "call_tool", fake_call_tool)
    client = _hub_client(monkeypatch)
    r = client.post("/api/security/engagements/nope/close")
    assert r.status_code == 404


# ---- RoE/SOW scope extraction (Phase E) ---------------------------------


def test_extract_candidate_targets_finds_ips_cidrs_and_domains():
    text = (
        "Authorized scope for this engagement includes 10.0.0.0/24 and "
        "203.0.113.5, plus the web properties app.example.com and "
        "example.com. The vendor's own status page, "
        "e.g. status.example.org, is explicitly out of scope."
    )
    got = set(secdash._extract_candidate_targets(text))
    assert "10.0.0.0/24" in got
    assert "203.0.113.5" in got
    assert "app.example.com" in got
    assert "example.com" in got
    assert "status.example.org" in got
    # Plain English prose isn't IP/CIDR- or domain-shaped at all, so it
    # never even reaches validate_ip/validate_domain to begin with.
    assert "engagement" not in got
    assert "vendor's" not in got


def test_extract_candidate_targets_filters_denylisted_footer_artifacts():
    got = secdash._extract_candidate_targets("Scope includes hosts, e.g. anything on the internal network.")
    assert "e.g" not in got


def test_extract_candidate_targets_empty_text_returns_empty_list():
    assert secdash._extract_candidate_targets("") == []


# ---- Temporal scope extraction (Phase I) --------------------------------


def test_extract_candidate_temporal_scope_finds_time_window():
    text = "Testing is authorized daily from 09:00 to 17:00, server-local time."
    got = secdash._extract_candidate_temporal_scope(text)
    assert got["authorized_hours"] == "09:00-17:00"
    assert got["blackout_dates"] == []


def test_extract_candidate_temporal_scope_normalizes_single_digit_hour():
    got = secdash._extract_candidate_temporal_scope("Window: 9:00-17:00.")
    assert got["authorized_hours"] == "09:00-17:00"


def test_extract_candidate_temporal_scope_finds_blackout_date_near_keyword():
    text = "No testing during the blackout period on 2026-12-25 (Christmas)."
    got = secdash._extract_candidate_temporal_scope(text)
    assert got["blackout_dates"] == ["2026-12-25"]


def test_extract_candidate_temporal_scope_ignores_dates_unrelated_to_blackout():
    # A best-effort heuristic (proximity to the word "blackout" in the same
    # sentence) -- dates in an unrelated sentence about the engagement's
    # own start/end aren't picked up as blackout candidates.
    text = "Engagement runs from 2026-08-01 through 2026-09-01. Scope is app.example.com."
    got = secdash._extract_candidate_temporal_scope(text)
    assert got["blackout_dates"] == []


def test_extract_candidate_temporal_scope_empty_text():
    assert secdash._extract_candidate_temporal_scope("") == {"authorized_hours": "", "blackout_dates": []}


def test_parse_roe_scope_route_includes_temporal_candidates(monkeypatch):
    import mcp_servers.pdf_server as pdf_mod
    monkeypatch.setattr(pdf_mod, "_PYPDF_AVAILABLE", True)
    monkeypatch.setattr(
        pdf_mod, "_pdf_extract_text",
        lambda file_path, pages, max_chars: "In scope: 10.0.0.0/24. Testing window 09:00-17:00. Blackout: 2026-12-25.",
    )
    client = _hub_client(monkeypatch)
    r = client.post("/api/security/roe/parse-scope", files={"file": ("roe.pdf", b"%PDF-1.4 fake", "application/pdf")})
    assert r.status_code == 200
    body = r.json()
    assert body["authorized_hours"] == "09:00-17:00"
    assert body["blackout_dates"] == ["2026-12-25"]


def test_parse_roe_scope_route_requires_admin(monkeypatch):
    client = _client_with_admin_gate(monkeypatch, _deny)
    r = client.post("/api/security/roe/parse-scope", files={"file": ("roe.pdf", b"%PDF-1.4 fake", "application/pdf")})
    assert r.status_code == 403


def test_parse_roe_scope_route_returns_candidates(monkeypatch):
    import mcp_servers.pdf_server as pdf_mod
    monkeypatch.setattr(pdf_mod, "_PYPDF_AVAILABLE", True)
    monkeypatch.setattr(pdf_mod, "_pdf_extract_text", lambda file_path, pages, max_chars: "In scope: 10.0.0.0/24 and app.example.com.")
    client = _hub_client(monkeypatch)
    r = client.post("/api/security/roe/parse-scope", files={"file": ("roe.pdf", b"%PDF-1.4 fake", "application/pdf")})
    assert r.status_code == 200
    body = r.json()
    assert "10.0.0.0/24" in body["candidates"]
    assert "app.example.com" in body["candidates"]
    assert body["extracted_chars"] > 0


def test_parse_roe_scope_route_cleans_up_temp_file(monkeypatch, tmp_path):
    import mcp_servers.pdf_server as pdf_mod
    monkeypatch.setattr(pdf_mod, "_PYPDF_AVAILABLE", True)
    monkeypatch.setattr(pdf_mod, "_DATA_DIR", tmp_path)

    def fake_extract(file_path, pages, max_chars):
        # The upload must exist on disk *while* extraction runs...
        assert (tmp_path / file_path).exists()
        return "10.0.0.1"

    monkeypatch.setattr(pdf_mod, "_pdf_extract_text", fake_extract)
    client = _hub_client(monkeypatch)
    r = client.post("/api/security/roe/parse-scope", files={"file": ("roe.pdf", b"%PDF-1.4 fake", "application/pdf")})
    assert r.status_code == 200
    # ...and be gone again afterward -- this is a scratch file, not a kept upload.
    assert list((tmp_path / "tmp_roe_uploads").iterdir()) == []


def test_parse_roe_scope_route_rejects_when_pypdf_unavailable(monkeypatch):
    import mcp_servers.pdf_server as pdf_mod
    monkeypatch.setattr(pdf_mod, "_PYPDF_AVAILABLE", False)
    client = _hub_client(monkeypatch)
    r = client.post("/api/security/roe/parse-scope", files={"file": ("roe.pdf", b"%PDF-1.4 fake", "application/pdf")})
    assert r.status_code == 400


def test_parse_roe_scope_route_no_extractable_text(monkeypatch):
    import mcp_servers.pdf_server as pdf_mod
    monkeypatch.setattr(pdf_mod, "_PYPDF_AVAILABLE", True)
    monkeypatch.setattr(pdf_mod, "_pdf_extract_text", lambda file_path, pages, max_chars: "(no extractable text — PDF may be scanned/image-only)")
    client = _hub_client(monkeypatch)
    r = client.post("/api/security/roe/parse-scope", files={"file": ("roe.pdf", b"%PDF-1.4 fake", "application/pdf")})
    assert r.status_code == 200
    assert r.json()["candidates"] == []


def test_list_watchlist_route(monkeypatch):
    import mcp_servers.watchlist_server as watchlist_mod
    rows = [{"id": 1, "indicator": "1.2.3.4", "kind": "ip"}]
    monkeypatch.setattr(watchlist_mod, "_list_watchlist", lambda kind, engagement_id, status: rows)
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/watchlist")
    assert r.status_code == 200
    assert r.json()["list"] == rows


@pytest.mark.asyncio
async def test_add_watchlist_route_validates_body(monkeypatch):
    client = _hub_client(monkeypatch)
    r = client.post("/api/security/watchlist", json={"kind": "ip"})  # missing indicator
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_remove_watchlist_route(monkeypatch):
    import mcp_servers.watchlist_server as watchlist_mod

    async def fake_call_tool(name, arguments):
        from mcp.types import TextContent
        assert name == "watchlist_remove"
        assert arguments["watchlist_id"] == 7
        return [TextContent(type="text", text="Removed watchlist entry 7.")]

    monkeypatch.setattr(watchlist_mod, "call_tool", fake_call_tool)
    client = _hub_client(monkeypatch)
    r = client.delete("/api/security/watchlist/7")
    assert r.status_code == 200


def test_get_watchlist_checks_route_parses_snapshot_json(monkeypatch):
    import mcp_servers.watchlist_server as watchlist_mod
    rows = [{"provider": "shodan", "snapshot": '{"ports": [22]}', "checked_at": 123.0}]
    monkeypatch.setattr(watchlist_mod, "_list_checks", lambda wid: rows)
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/watchlist/1/checks")
    assert r.status_code == 200
    assert r.json()["checks"][0]["snapshot"] == {"ports": [22]}


def test_list_sigma_rules_route(monkeypatch):
    import mcp_servers.sigma_server as sigma_mod
    monkeypatch.setattr(sigma_mod, "_list_rules", lambda: ["rule_a", "rule_b"])
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/rules/sigma")
    assert r.status_code == 200
    assert r.json()["list"] == ["rule_a", "rule_b"]


def test_get_sigma_rule_route_not_found(monkeypatch):
    import mcp_servers.sigma_server as sigma_mod
    monkeypatch.setattr(sigma_mod, "_read_rule", lambda name: (None, "[error:not_found] no such rule"))
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/rules/sigma/nope")
    assert r.status_code == 404


def test_list_yara_rules_route_reports_sidecar_unreachable(monkeypatch):
    import mcp_servers.yara_server as yara_mod
    monkeypatch.setattr(yara_mod, "_list_rule_names", lambda: None)
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/rules/yara")
    assert r.status_code == 200
    body = r.json()
    assert body["list"] == []
    assert "error" in body


def test_get_yara_rule_route(monkeypatch):
    import mcp_servers.yara_server as yara_mod
    monkeypatch.setattr(yara_mod, "_read_rule", lambda name: ("rule Test { condition: true }", None))
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/rules/yara/my_rule")
    assert r.status_code == 200
    assert "rule Test" in r.json()["content"]


# ---- Connected Services (Security Hub page follow-up) ---------------------


def test_list_connected_services_route_requires_admin(monkeypatch):
    monkeypatch.setattr(secdash, "require_admin", _deny)
    app = FastAPI()
    app.include_router(secdash.setup_security_dashboard_routes())
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/api/security/services")
    assert r.status_code == 403


def test_list_connected_services_route_reports_reachability(monkeypatch):
    def fake_probe(url):
        # bentopdf's probe_url is the only one that "succeeds" in this test.
        return "odysseus-bentopdf" in url

    monkeypatch.setattr(secdash, "_probe_service", fake_probe)
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/services")
    assert r.status_code == 200
    services = {s["id"]: s for s in r.json()["services"]}

    assert set(services) == {"bentopdf", "cyberchef", "spiderfoot", "opensearch", "ollama", "toolchain"}
    assert services["bentopdf"]["reachable"] is True
    assert services["spiderfoot"]["reachable"] is False
    # probe_url is an internal implementation detail -- never leaked to the client.
    assert "probe_url" not in services["bentopdf"]


def test_connected_services_toolchain_has_no_browser_url(monkeypatch):
    """The toolchain's exec API accepts arbitrary command execution and must
    never be offered as a clickable browser link, reachable or not."""
    monkeypatch.setattr(secdash, "_probe_service", lambda url: True)
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/services")
    services = {s["id"]: s for s in r.json()["services"]}
    assert services["toolchain"]["browser_url"] is None
    for svc_id in ("bentopdf", "cyberchef", "spiderfoot", "opensearch", "ollama"):
        assert services[svc_id]["browser_url"], f"{svc_id} should expose a browser_url"


def test_probe_service_handles_connection_failure():
    # No mocking -- a real request to a closed local port must return False,
    # not raise, so one unreachable sidecar can't break the whole panel.
    assert secdash._probe_service("http://127.0.0.1:1") is False


# ---- Audit Log ---------------------------------------------------------------


def test_list_audit_log_route_requires_admin(monkeypatch):
    monkeypatch.setattr(secdash, "require_admin", _deny)
    app = FastAPI()
    app.include_router(secdash.setup_security_dashboard_routes())
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/api/security/audit")
    assert r.status_code == 403


def test_list_audit_log_route_returns_invocations_and_stats(monkeypatch):
    import mcp_servers.audit_server as audit_mod
    rows = [{"id": 1, "binary": "nmap", "args": ["nmap", "10.0.0.5"], "outcome": "ok"}]
    stats = {"total": 1, "by_binary": [{"binary": "nmap", "n": 1}], "by_outcome": [{"outcome": "ok", "n": 1}]}
    monkeypatch.setattr(audit_mod, "_list_invocations", lambda binary, outcome, engagement_id, limit: rows)
    monkeypatch.setattr(audit_mod, "_stats", lambda window_s: stats)
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/audit")
    assert r.status_code == 200
    body = r.json()
    assert body["invocations"] == rows
    assert body["stats"]["total"] == 1


def test_list_audit_log_route_passes_filters_through(monkeypatch):
    import mcp_servers.audit_server as audit_mod
    seen = {}

    def fake_list(binary, outcome, engagement_id, limit):
        seen["args"] = (binary, outcome, engagement_id, limit)
        return []

    monkeypatch.setattr(audit_mod, "_list_invocations", fake_list)
    monkeypatch.setattr(audit_mod, "_stats", lambda window_s: {"total": 0, "by_binary": [], "by_outcome": []})
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/audit?binary=nmap&outcome=error&engagement_id=eng-1&limit=10")
    assert r.status_code == 200
    assert seen["args"] == ("nmap", "error", "eng-1", 10)


def test_list_audit_log_route_engagement_filter_against_real_audit_db(monkeypatch, tmp_path):
    """Regression: the route used to call _list_invocations(binary, outcome,
    limit) *positionally*; adding an engagement_id parameter before limit
    (Phase A) silently landed `limit` in the engagement_id slot for this
    exact call site (every other test here mocks _list_invocations
    entirely, so none of them would have caught it). Exercises the real,
    unmocked function against a real isolated audit.db instead."""
    import importlib
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    import mcp_servers.common as common_mod
    import mcp_servers.audit_server as audit_mod
    importlib.reload(common_mod)
    importlib.reload(audit_mod)
    monkeypatch.setattr(secdash, "require_admin", _allow)

    common_mod._log_invocation("nmap", ["nmap", "10.0.0.5"], "container", 100, "ok", engagement_id="eng-1")
    common_mod._log_invocation("nmap", ["nmap", "10.0.0.6"], "container", 100, "ok", engagement_id="eng-2")

    app = FastAPI()
    app.include_router(secdash.setup_security_dashboard_routes())
    client = TestClient(app, raise_server_exceptions=False)

    r = client.get("/api/security/audit?engagement_id=eng-1&limit=10")
    assert r.status_code == 200
    body = r.json()
    assert len(body["invocations"]) == 1
    assert body["invocations"][0]["engagement_id"] == "eng-1"
    assert body["invocations"][0]["args"] == ["nmap", "10.0.0.5"]


def test_list_audit_log_route_clamps_limit(monkeypatch):
    import mcp_servers.audit_server as audit_mod
    seen = {}

    def fake_list(binary, outcome, engagement_id, limit):
        seen["limit"] = limit
        return []

    monkeypatch.setattr(audit_mod, "_list_invocations", fake_list)
    monkeypatch.setattr(audit_mod, "_stats", lambda window_s: {"total": 0, "by_binary": [], "by_outcome": []})
    client = _hub_client(monkeypatch)
    r = client.get("/api/security/audit?limit=5000")
    assert r.status_code == 200
    assert seen["limit"] == 500
