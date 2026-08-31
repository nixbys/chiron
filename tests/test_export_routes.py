"""Route-level regression tests for /api/security/export/*.

Same pattern tests/test_security_dashboard_route.py already establishes: a
real FastAPI + TestClient mounting just this router, with require_admin
patched directly on the route module and each mcp_servers.* module's own
structured helper patched on that module object (export_routes.py imports
mcp_servers.* fresh inside each handler, but that's still the same
singleton module object from sys.modules -- patching its attribute here
still takes effect there)."""

import io
import json
import zipfile
from unittest.mock import AsyncMock

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
    # Best-effort notification -- exercised on its own further down;
    # every other test just needs it to be a no-op so it doesn't touch
    # real settings/SMTP/ntfy config.
    monkeypatch.setattr(export_routes, "_notify_export_complete", AsyncMock(return_value=None))
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
    monkeypatch.setattr(engagement_mod, "_get_timeline", lambda eid, limit: [{"event_type": "note", "summary": "x", "ts": 1000}])
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
    r = client.post("/api/security/export/engagement/eng-1")
    assert r.status_code == 403


def test_export_engagement_404_for_unknown_id(monkeypatch):
    _patch_common_sources(monkeypatch, engagement=None)
    client = _client(monkeypatch)
    r = client.post("/api/security/export/engagement/no-such-id")
    assert r.status_code == 404


def test_export_engagement_returns_zip_with_expected_entries(monkeypatch):
    _patch_common_sources(monkeypatch)
    client = _client(monkeypatch)
    r = client.post("/api/security/export/engagement/eng-1")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    assert "attachment" in r.headers["content-disposition"]

    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(zf.namelist())
    assert {"engagement.json", "findings.json", "assets.json", "watchlist.json",
            "audit_log.json", "manifest.json", "SUMMARY.md"} <= names
    # No PDF entry -- _generate_engagement_report was mocked to fail above.
    assert "report.pdf" not in names

    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["engagement_id"] == "eng-1"
    assert manifest["counts"]["findings"] == 1
    assert manifest["report_included"] is False

    findings = json.loads(zf.read("findings.json"))
    assert findings[0]["title"] == "Open SSH"

    summary = zf.read("SUMMARY.md").decode()
    assert "Demo Engagement" in summary
    assert "Open SSH" in summary


def test_export_engagement_includes_report_when_generation_succeeds(monkeypatch, tmp_path):
    _patch_common_sources(monkeypatch)
    report_bytes = b"%PDF-1.4 fake report"
    report_file = tmp_path / "reports" / "export_eng-1.pdf"
    report_file.parent.mkdir(parents=True)
    report_file.write_bytes(report_bytes)

    monkeypatch.setattr(pdf_mod, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(pdf_mod, "_generate_engagement_report", lambda *a, **kw: "Report saved: export_eng-1.pdf")

    client = _client(monkeypatch)
    r = client.post("/api/security/export/engagement/eng-1")
    assert r.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    assert zf.read("report.pdf") == report_bytes

    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["report_included"] is True


def test_export_all_requires_admin(monkeypatch):
    client = _client(monkeypatch, gate=_deny)
    r = client.post("/api/security/export/all")
    assert r.status_code == 403


def test_export_all_returns_zip_with_expected_entries(monkeypatch, tmp_path):
    _patch_common_sources(monkeypatch)
    monkeypatch.setattr(pdf_mod, "_DATA_DIR", tmp_path)
    client = _client(monkeypatch)
    r = client.post("/api/security/export/all")
    assert r.status_code == 200

    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(zf.namelist())
    assert {"engagements.json", "findings.json", "assets.json", "watchlist.json",
            "audit_log.json", "manifest.json", "SUMMARY.md"} <= names

    engagements = json.loads(zf.read("engagements.json"))
    assert engagements[0]["id"] == "eng-1"
    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["scope"] == "all"


# ---- Passphrase encryption -----------------------------------------------


def test_export_engagement_with_passphrase_is_encrypted(monkeypatch):
    _patch_common_sources(monkeypatch)
    client = _client(monkeypatch)
    r = client.post("/api/security/export/engagement/eng-1", json={"passphrase": "correct horse battery staple"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/octet-stream"
    assert ".chiron-export" in r.headers["content-disposition"]

    # Not a valid zip on its own -- it's wrapped.
    with pytest.raises(zipfile.BadZipFile):
        zipfile.ZipFile(io.BytesIO(r.content))

    plaintext = export_routes.decrypt_export_bytes(r.content, "correct horse battery staple")
    zf = zipfile.ZipFile(io.BytesIO(plaintext))
    assert "manifest.json" in zf.namelist()


def test_export_engagement_with_passphrase_wrong_passphrase_fails(monkeypatch):
    _patch_common_sources(monkeypatch)
    client = _client(monkeypatch)
    r = client.post("/api/security/export/engagement/eng-1", json={"passphrase": "right"})
    with pytest.raises(ValueError):
        export_routes.decrypt_export_bytes(r.content, "wrong")


def test_export_engagement_without_passphrase_is_plain_zip(monkeypatch):
    _patch_common_sources(monkeypatch)
    client = _client(monkeypatch)
    r = client.post("/api/security/export/engagement/eng-1", json={})
    assert r.headers["content-type"] == "application/zip"
    zipfile.ZipFile(io.BytesIO(r.content))  # must not raise


# ---- Export-completion notification ---------------------------------------


def test_export_engagement_fires_notification(monkeypatch):
    _patch_common_sources(monkeypatch)
    notify = AsyncMock(return_value=None)
    monkeypatch.setattr(export_routes, "require_admin", _allow)
    monkeypatch.setattr(export_routes, "get_current_user", lambda request: "admin")
    monkeypatch.setattr(export_routes, "_notify_export_complete", notify)
    app = FastAPI()
    app.include_router(export_routes.setup_export_routes())
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post("/api/security/export/engagement/eng-1")
    assert r.status_code == 200
    notify.assert_awaited_once_with(engagement_id="eng-1", user="admin")


@pytest.mark.asyncio
async def test_notify_export_complete_failure_does_not_raise(monkeypatch):
    """Best-effort: dispatch_reminder blowing up must not propagate --
    the export itself has already succeeded by the time this runs."""
    import routes.note_routes as note_routes_mod
    monkeypatch.setattr(note_routes_mod, "dispatch_reminder", AsyncMock(side_effect=RuntimeError("smtp down")))
    await export_routes._notify_export_complete(engagement_id="eng-1", user="admin")  # must not raise


# ---- Wipe routes ------------------------------------------------------------


def test_wipe_engagement_requires_admin(monkeypatch):
    client = _client(monkeypatch, gate=_deny)
    r = client.delete("/api/security/export/engagement/eng-1?confirm=true")
    assert r.status_code == 403


def test_wipe_engagement_requires_confirm(monkeypatch):
    _patch_common_sources(monkeypatch)
    client = _client(monkeypatch)
    r = client.delete("/api/security/export/engagement/eng-1")
    assert r.status_code == 400


def test_wipe_engagement_404_for_unknown_id(monkeypatch):
    _patch_common_sources(monkeypatch, engagement=None)
    client = _client(monkeypatch)
    r = client.delete("/api/security/export/engagement/no-such-id?confirm=true")
    assert r.status_code == 404


def test_wipe_engagement_calls_wipe_and_returns_counts(monkeypatch):
    _patch_common_sources(monkeypatch)
    monkeypatch.setattr(export_routes, "_wipe_engagement_data", lambda eid: {"findings": 3, "assets": 1})
    client = _client(monkeypatch)
    r = client.delete("/api/security/export/engagement/eng-1?confirm=true")
    assert r.status_code == 200
    body = r.json()
    assert body["wiped"] is True
    assert body["engagement_id"] == "eng-1"
    assert body["counts"] == {"findings": 3, "assets": 1}


def test_wipe_all_requires_confirm(monkeypatch):
    client = _client(monkeypatch)
    r = client.delete("/api/security/export/all")
    assert r.status_code == 400


def test_wipe_all_requires_admin(monkeypatch):
    client = _client(monkeypatch, gate=_deny)
    r = client.delete("/api/security/export/all?confirm=true")
    assert r.status_code == 403


def test_wipe_all_calls_wipe_and_returns_counts(monkeypatch):
    monkeypatch.setattr(export_routes, "_wipe_all_data", lambda: {"engagements": 5})
    client = _client(monkeypatch)
    r = client.delete("/api/security/export/all?confirm=true")
    assert r.status_code == 200
    body = r.json()
    assert body["wiped"] is True
    assert body["scope"] == "all"
    assert body["counts"] == {"engagements": 5}


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


# ---- Encrypt/decrypt helpers ------------------------------------------------


def test_encrypt_export_bytes_round_trips():
    data = b"some zip bytes, pretend"
    enc = export_routes.encrypt_export_bytes(data, "hunter2")
    assert enc.startswith(export_routes._EXPORT_MAGIC)
    assert export_routes.decrypt_export_bytes(enc, "hunter2") == data


def test_decrypt_export_bytes_wrong_passphrase_raises():
    enc = export_routes.encrypt_export_bytes(b"data", "right")
    with pytest.raises(ValueError, match="assphrase"):
        export_routes.decrypt_export_bytes(enc, "wrong")


def test_decrypt_export_bytes_rejects_non_chiron_file():
    with pytest.raises(ValueError, match="header"):
        export_routes.decrypt_export_bytes(b"not a chiron export at all", "whatever")
