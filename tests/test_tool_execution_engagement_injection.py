"""Phase B: src/tool_execution.py injects a session's engagement_id into
scope-enforced MCP tool calls, mirroring the existing _EMAIL_MCP_OWNER_ARG
precedent -- see test_review_regressions.py's test_email_mcp_dispatch_
includes_hidden_owner for that sibling test.

Uses an isolated temp-file SQLite DB via monkeypatch.setattr on
SessionLocal (see test_session_engagement_routes.py's app_env fixture for
why this doesn't reload core.database itself)."""

import types

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import pytest

import core.database as database
import core.session_manager as sm_mod
import src.tool_execution as tool_execution


class _FakeMcp:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, args):
        self.calls.append((name, args))
        return {"output": "called", "exit_code": 0}


@pytest.fixture
def db_env(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    database.Base.metadata.create_all(bind=engine)
    TestSessionLocal = sessionmaker(bind=engine)

    monkeypatch.setattr(sm_mod, "SessionLocal", TestSessionLocal)
    # tool_execution._session_engagement_id imports SessionLocal fresh from
    # core.database on every call (a local import, not a module-level
    # name) -- patching it here is what that lookup actually sees.
    monkeypatch.setattr(database, "SessionLocal", TestSessionLocal)

    fake = _FakeMcp()
    monkeypatch.setattr(tool_execution, "get_mcp_manager", lambda: fake)
    monkeypatch.setattr(tool_execution, "_owner_is_admin", lambda owner: True)
    # Phase K's unscoped-session nudge state is a module-level set (best-
    # effort, process-lifetime) -- reset it so one test's nudge doesn't
    # consume another's.
    monkeypatch.setattr(tool_execution, "_nudged_unscoped_sessions", set())

    manager = sm_mod.SessionManager()
    yield tool_execution, manager, fake


async def _run(tool_execution, tool_type, content, session_id=None):
    # Use tool_execution.NO_TOOL_SECURITY_CONTEXT (the same module object
    # execute_tool_block's own `is` identity check runs against), not a
    # fresh `from src.tool_execution import ...` -- if any other test file
    # elsewhere pops/reimports sys.modules['src.tool_execution'] between
    # this fixture's own import and this call, a fresh import would fetch a
    # *different* module instance's sentinel, which never compares equal
    # via `is` to what execute_tool_block checks against.
    return await tool_execution.execute_tool_block(
        types.SimpleNamespace(tool_type=tool_type, content=content),
        session_id=session_id,
        owner="admin-user",
        security_context=tool_execution.NO_TOOL_SECURITY_CONTEXT,
    )


@pytest.mark.asyncio
async def test_scoped_tool_gets_engagement_id_injected_from_session(db_env):
    tool_execution, manager, fake = db_env
    manager.create_session(
        session_id="s1", name="t", endpoint_url="x", model="m",
        engagement_id="eng-1",
    )

    desc, result = await _run(
        tool_execution, "mcp__abc123__nmap_scan", '{"target": "10.0.0.5"}', session_id="s1",
    )

    assert result["exit_code"] == 0
    assert fake.calls == [
        ("mcp__abc123__nmap_scan", {"target": "10.0.0.5", "engagement_id": "eng-1"}),
    ]


@pytest.mark.asyncio
async def test_unscoped_tool_name_is_not_touched(db_env):
    """A tool name outside _ENGAGEMENT_SCOPED_MCP_TOOLS (e.g. cve_lookup,
    which has no target) never gets an engagement_id injected, even with a
    linked session."""
    tool_execution, manager, fake = db_env
    manager.create_session(
        session_id="s1", name="t", endpoint_url="x", model="m",
        engagement_id="eng-1",
    )

    await _run(tool_execution, "mcp__abc123__cve_lookup", '{"query": "log4j"}', session_id="s1")

    assert fake.calls == [("mcp__abc123__cve_lookup", {"query": "log4j"})]


@pytest.mark.asyncio
async def test_session_with_no_engagement_injects_nothing(db_env):
    tool_execution, manager, fake = db_env
    manager.create_session(session_id="s1", name="t", endpoint_url="x", model="m")

    await _run(tool_execution, "mcp__abc123__nmap_scan", '{"target": "10.0.0.5"}', session_id="s1")

    assert fake.calls == [("mcp__abc123__nmap_scan", {"target": "10.0.0.5"})]


@pytest.mark.asyncio
async def test_model_supplied_engagement_id_always_wins(db_env):
    """A model can work against a different engagement in the same session
    -- an explicit engagement_id in the tool call always wins over the
    session's own, per the plan's setdefault-equivalent semantics."""
    tool_execution, manager, fake = db_env
    manager.create_session(
        session_id="s1", name="t", endpoint_url="x", model="m",
        engagement_id="eng-1",
    )

    await _run(
        tool_execution,
        "mcp__abc123__nmap_scan",
        '{"target": "10.0.0.5", "engagement_id": "eng-2"}',
        session_id="s1",
    )

    assert fake.calls == [
        ("mcp__abc123__nmap_scan", {"target": "10.0.0.5", "engagement_id": "eng-2"}),
    ]


@pytest.mark.asyncio
async def test_no_session_id_injects_nothing(db_env):
    tool_execution, _, fake = db_env

    await _run(tool_execution, "mcp__abc123__nmap_scan", '{"target": "10.0.0.5"}', session_id=None)

    assert fake.calls == [("mcp__abc123__nmap_scan", {"target": "10.0.0.5"})]


# ---- Unscoped-session nudge (Phase K) -----------------------------------


@pytest.mark.asyncio
async def test_unscoped_session_gets_nudged_on_first_scoped_tool_call(db_env):
    tool_execution, manager, fake = db_env
    manager.create_session(session_id="s1", name="t", endpoint_url="x", model="m")

    desc, result = await _run(
        tool_execution, "mcp__abc123__nmap_scan", '{"target": "10.0.0.5"}', session_id="s1",
    )

    assert "isn't linked to a Project" in result["stdout"]


@pytest.mark.asyncio
async def test_unscoped_session_nudge_does_not_repeat(db_env):
    tool_execution, manager, fake = db_env
    manager.create_session(session_id="s1", name="t", endpoint_url="x", model="m")

    await _run(tool_execution, "mcp__abc123__nmap_scan", '{"target": "10.0.0.5"}', session_id="s1")
    desc, result = await _run(
        tool_execution, "mcp__abc123__nmap_scan", '{"target": "10.0.0.6"}', session_id="s1",
    )

    assert "isn't linked to a Project" not in result.get("stdout", "")


@pytest.mark.asyncio
async def test_scoped_session_never_gets_nudged(db_env):
    tool_execution, manager, fake = db_env
    manager.create_session(
        session_id="s1", name="t", endpoint_url="x", model="m", engagement_id="eng-1",
    )

    desc, result = await _run(
        tool_execution, "mcp__abc123__nmap_scan", '{"target": "10.0.0.5"}', session_id="s1",
    )

    assert "isn't linked to a Project" not in result.get("stdout", "")


@pytest.mark.asyncio
async def test_unscoped_tool_name_does_not_trigger_nudge(db_env):
    """A tool outside _ENGAGEMENT_SCOPED_MCP_TOOLS (no scope concept at
    all) never nudges, even on an unscoped session."""
    tool_execution, manager, fake = db_env
    manager.create_session(session_id="s1", name="t", endpoint_url="x", model="m")

    desc, result = await _run(
        tool_execution, "mcp__abc123__cve_lookup", '{"query": "log4j"}', session_id="s1",
    )

    assert "isn't linked to a Project" not in result.get("stdout", "")


@pytest.mark.asyncio
async def test_no_session_id_does_not_trigger_nudge(db_env):
    tool_execution, _, fake = db_env

    desc, result = await _run(
        tool_execution, "mcp__abc123__nmap_scan", '{"target": "10.0.0.5"}', session_id=None,
    )

    assert "isn't linked to a Project" not in result.get("stdout", "")


@pytest.mark.asyncio
async def test_nudge_is_independent_per_session(db_env):
    tool_execution, manager, fake = db_env
    manager.create_session(session_id="s1", name="t", endpoint_url="x", model="m")
    manager.create_session(session_id="s2", name="t2", endpoint_url="x", model="m")

    await _run(tool_execution, "mcp__abc123__nmap_scan", '{"target": "10.0.0.5"}', session_id="s1")
    desc, result = await _run(
        tool_execution, "mcp__abc123__nmap_scan", '{"target": "10.0.0.6"}', session_id="s2",
    )

    assert "isn't linked to a Project" in result["stdout"]


@pytest.mark.asyncio
async def test_secrets_scan_is_in_engagement_scoped_tools():
    """Regression: secrets_scan (Phase H) was added to osint_server's own
    check_scope_from_args wiring but never to this set, so a linked
    session's engagement_id was silently never auto-injected into it."""
    assert "secrets_scan" in tool_execution._ENGAGEMENT_SCOPED_MCP_TOOLS
