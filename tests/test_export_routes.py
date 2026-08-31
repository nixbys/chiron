"""Route-level regression tests for GET /api/security/export/*.

Same pattern tests/test_security_dashboard_route.py already establishes: a
real FastAPI + TestClient mounting just this router, with require_admin
patched directly on the route module and each mcp_servers.* module's own
structured helper patched on that module object (export_routes.py imports
mcp_servers.* fresh inside each handler, but that's still the same
singleton module object from sys.modules -- patching its attribute here
still takes effect there)."""

import io
import zipfile

import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("starlette.testclient")

from fastapi import FastAPI, HTTPException, Request
from starlette.testclient import TestClient

export_routes = pytest.importorskip("routes.export_routes")

import mcp_servers.asset_server as asset_mod
import mcp_servers.audit_server as audit_mod
import mcp_servers.engagement_server as engagement_mod
import mcp_servers.findings_server as findings_mod
import mcp_servers.pdf_server as pdf_mod
import mcp_servers.watchlist_server as watchlist_mod


def _allow(_request: Request):
    return None


def _deny(_request: Request):
    raise HTTPException(403, "Admin only")


def _client(monkeypatch, gate=_allow):
    monkeypatch.setattr(export_routes, "require_admin", gate)
    monkeypatch.setattr(export_routes, "get_current_user", lambda request: "admin")
    app = FastAPI()
    app.include_router(export_routes.setup_export_routes())
    return TestClient(app, raise_server_exceptions=False)


_ENGAGEMENT = {
    "id": "eng-1", "name": "Demo Engagement", "description": "", "client": "",
    "scope": "[]", "out_of_scope": "[]", "tags": "[]", "blackout_dates": "[]",
    "status": "active", "authorized_hours": "",
}


def _patch_common_sources(monkeypatch, *, engagement=_ENGAGEMENT):
    monkeypatch.setattr(engagement_mod, "_get_engagement", lambda eid: dict(engagement) if engagement else None)
    monkeypatch.setattr(engagement_mod, "_get_timeline", lambda eid, limit: [{"event_type": "note", "summary": "x"}])
    monkeypatch.setattr(engagement_mod, "_list_engagements", lambda status, limit: [{"id": "eng-1", "name": "Demo Engagement"}])
    monkeypatch.setattr(audit_mod, "_list_invocations", lambda **kw: [
        {"id": 1, "binary": "nmap", "outcome": "ok", "raw_log_path": None},
    ])
    monkeypatch.setattr(findings_mod, "_export_findings", lambda **kw: [{"title": "Open SSH", "severity": "low"}])
    monkeypatch.setattr(asset_mod, "_export_data", lambda **kw: {"assets": [{"ip": "10.0.0.1"}], "services": [], "findings": []})
    monkeypatch.setattr(watchlist_mod, "_list_watchlist", lambda *a, **kw: [{"indicator": "10.0.0.1", "kind": "ip"}])
    monkeypatch.setattr(pdf_mod, "_generate_engagement_report", lambda *a, **kw: "[error] pypdf not installed")


def test_export_engagement_requires_admin(monkeypatch):
    client = _client(monkeypatch, gate=_deny)
    r = client.get("/api/security/export/engagement/eng-1")
    assert r.status_code == 403


def test_export_engagement_404_for_unknown_id(monkeypatch):
    _patch_common_sources(monkeypatch, engagement=None)
    client = _client(monkeypatch)
    r = client.get("/api/security/export/engagement/no-such-id")
    assert r.status_code == 404


def test_export_engagement_returns_zip_with_expected_entries(monkeypatch):
    _patch_common_sources(monkeypatch)
    client = _client(monkeypatch)
    r = client.get("/api/security/export/engagement/eng-1")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    assert "attachment" in r.headers["content-disposition"]

    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(zf.namelist())
    assert {"engagement.json", "findings.json", "assets.json", "watchlist.json", "audit_log.json", "manifest.json"} <= names
    # No PDF entry -- _generate_engagement_report was mocked to fail above.
    assert "report.pdf" not in names

    import json
    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["engagement_id"] == "eng-1"
    assert manifest["counts"]["findings"] == 1
    assert manifest["report_included"] is False

    findings = json.loads(zf.read("findings.json"))
    assert findings[0]["title"] == "Open SSH"


def test_export_engagement_includes_report_when_generation_succeeds(monkeypatch, tmp_path):
    _patch_common_sources(monkeypatch)
    report_bytes = b"%PDF-1.4 fake report"
    report_file = tmp_path / "reports" / "export_eng-1.pdf"
    report_file.parent.mkdir(parents=True)
    report_file.write_bytes(report_bytes)

    monkeypatch.setattr(pdf_mod, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(pdf_mod, "_generate_engagement_report", lambda *a, **kw: "Report saved: export_eng-1.pdf")

    client = _client(monkeypatch)
    r = client.get("/api/security/export/engagement/eng-1")
    assert r.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    assert zf.read("report.pdf") == report_bytes

    import json
    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["report_included"] is True


def test_export_all_requires_admin(monkeypatch):
    client = _client(monkeypatch, gate=_deny)
    r = client.get("/api/security/export/all")
    assert r.status_code == 403


def test_export_all_returns_zip_with_expected_entries(monkeypatch, tmp_path):
    _patch_common_sources(monkeypatch)
    monkeypatch.setattr(pdf_mod, "_DATA_DIR", tmp_path)
    client = _client(monkeypatch)
    r = client.get("/api/security/export/all")
    assert r.status_code == 200

    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(zf.namelist())
    assert {"engagements.json", "findings.json", "assets.json", "watchlist.json", "audit_log.json", "manifest.json"} <= names

    import json
    engagements = json.loads(zf.read("engagements.json"))
    assert engagements[0]["id"] == "eng-1"
    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["scope"] == "all"


# ---- _add_raw_logs / _add_rule_files -----------------------------------------


def test_add_raw_logs_skips_entries_with_no_path_or_missing_file(monkeypatch, tmp_path):
    import mcp_servers.common as common_mod
    monkeypatch.setattr(common_mod, "_DATA_DIR", tmp_path)
    (tmp_path / "audit_logs").mkdir()
    (tmp_path / "audit_logs" / "1_nmap_abcd.log").write_text("full nmap output")

    invocations = [
        {"id": 1, "binary": "nmap", "raw_log_path": "audit_logs/1_nmap_abcd.log"},
        {"id": 2, "binary": "whois", "raw_log_path": None},
        {"id": 3, "binary": "dig", "raw_log_path": "audit_logs/does_not_exist.log"},
    ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        count = export_routes._add_raw_logs(zf, invocations)
    assert count == 1
    buf.seek(0)
    zf = zipfile.ZipFile(buf)
    assert zf.read("raw_logs/1_nmap.log").decode() == "full nmap output"
    assert "raw_logs/2_whois.log" not in zf.namelist()
    assert "raw_logs/3_dig.log" not in zf.namelist()
