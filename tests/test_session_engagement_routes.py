"""Tests for Phase B's session<->engagement wiring: /api/session accepting
an engagement_id at creation, and PATCH /api/session/{sid} attach/detach.

Uses a real, isolated temp-file SQLite DB (TestClient runs the ASGI app in
its own thread, and SQLite's :memory: is per-connection/per-thread, so a
real file is needed) -- but via monkeypatch.setattr on SessionLocal rather
than reloading core.database itself. Reloading that module recreates its
Base/engine from scratch, which would also blow away the shared in-memory
DB every *other* test file relies on (core.database is a process-wide
singleton) -- monkeypatch's own auto-revert keeps this test fully isolated
without that blast radius.

Also swaps in a fresh APIRouter before calling setup_session_routes():
routes/session_routes.py's `router` is a module-level singleton every
@router.post/@router.patch decorator registers onto, and setup_session_
routes() is meant to be called exactly once per process (real app
startup). Another test file (test_archived_sessions_model_filter.py) also
calls it, with a MagicMock() standing in for session_manager -- without a
fresh router here, Starlette's first-match routing would dispatch this
test's requests to *that* stale MagicMock-bound handler instead of the
real one just registered."""

from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import pytest

import core.database as database
import core.session_manager as sm_mod
import routes.session_routes as session_routes


@pytest.fixture
def app_env(monkeypatch, tmp_path):
    monkeypatch.setattr(session_routes, "router", APIRouter(prefix="/api", tags=["sessions"]))
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    database.Base.metadata.create_all(bind=engine)
    TestSessionLocal = sessionmaker(bind=engine)

    monkeypatch.setattr(sm_mod, "SessionLocal", TestSessionLocal)
    monkeypatch.setattr(session_routes, "SessionLocal", TestSessionLocal)
    # Bypass auth/ownership checks -- not what this test is about, same
    # pattern test_history_compact_tool_calls.py uses.
    monkeypatch.setattr(session_routes, "_verify_session_owner", lambda request, session_id, session_manager=None: None)

    manager = sm_mod.SessionManager()
    app = FastAPI()
    app.include_router(session_routes.setup_session_routes(manager, config={}))
    client = TestClient(app)
    yield client, TestSessionLocal


def test_create_session_with_engagement_id_persists_it(app_env):
    client, TestSessionLocal = app_env
    resp = client.post("/api/session", data={
        "name": "recon chat",
        "skip_validation": "true",
        "engagement_id": "eng-1",
    })
    assert resp.status_code == 200
    sid = resp.json()["id"]

    db = TestSessionLocal()
    try:
        row = db.query(database.Session).filter(database.Session.id == sid).first()
    finally:
        db.close()
    assert row is not None
    assert row.engagement_id == "eng-1"


def test_create_session_without_engagement_id_leaves_it_unset(app_env):
    client, TestSessionLocal = app_env
    resp = client.post("/api/session", data={"name": "unscoped chat", "skip_validation": "true"})
    assert resp.status_code == 200
    sid = resp.json()["id"]

    db = TestSessionLocal()
    try:
        row = db.query(database.Session).filter(database.Session.id == sid).first()
    finally:
        db.close()
    assert row.engagement_id is None


def test_patch_session_attaches_engagement(app_env):
    client, TestSessionLocal = app_env
    sid = client.post("/api/session", data={"name": "chat", "skip_validation": "true"}).json()["id"]

    resp = client.patch(f"/api/session/{sid}", data={"engagement_id": "eng-2"})
    assert resp.status_code == 200
    assert resp.json()["engagement_id"] == "eng-2"

    db = TestSessionLocal()
    try:
        row = db.query(database.Session).filter(database.Session.id == sid).first()
    finally:
        db.close()
    assert row.engagement_id == "eng-2"


def test_patch_session_detaches_engagement_with_explicit_flag(app_env):
    client, TestSessionLocal = app_env
    sid = client.post("/api/session", data={
        "name": "chat", "skip_validation": "true", "engagement_id": "eng-3",
    }).json()["id"]

    resp = client.patch(f"/api/session/{sid}", data={"detach_engagement": "true"})
    assert resp.status_code == 200
    assert resp.json()["engagement_id"] is None

    db = TestSessionLocal()
    try:
        row = db.query(database.Session).filter(database.Session.id == sid).first()
    finally:
        db.close()
    assert row.engagement_id is None


def test_patch_session_omitting_engagement_id_leaves_it_untouched(app_env):
    client, TestSessionLocal = app_env
    sid = client.post("/api/session", data={
        "name": "chat", "skip_validation": "true", "engagement_id": "eng-4",
    }).json()["id"]

    resp = client.patch(f"/api/session/{sid}", data={"name": "renamed"})
    assert resp.status_code == 200
    assert "engagement_id" not in resp.json()

    db = TestSessionLocal()
    try:
        row = db.query(database.Session).filter(database.Session.id == sid).first()
    finally:
        db.close()
    assert row.engagement_id == "eng-4"
