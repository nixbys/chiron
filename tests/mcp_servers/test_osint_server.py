"""Unit tests for osint_server.py's secrets_scan tool (Phase H) -- mock the
exec API HTTP call so no real container/git/gitleaks install is needed.
Pre-existing tools (harvester, dns_enum, etc.) aren't covered here; this
file is scoped to the new tool and its scope-enforcement wiring."""

import importlib
import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp_servers import common
from mcp_servers.osint_server import _git_repo_host, call_tool


def _make_response(stdout: str = "", stderr: str = "", returncode: int = 0, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {"stdout": stdout, "stderr": stderr, "returncode": returncode}
    resp.raise_for_status = MagicMock()
    return resp


# ---- _git_repo_host ----------------------------------------------------


def test_git_repo_host_https():
    assert _git_repo_host("https://github.com/org/repo.git") == "github.com"


def test_git_repo_host_scp_like():
    assert _git_repo_host("git@github.com:org/repo.git") == "github.com"


def test_git_repo_host_unrecognized_returns_none():
    assert _git_repo_host("not a url at all") is None


# ---- secrets_scan --------------------------------------------------------


@pytest.mark.asyncio
async def test_secrets_scan_rejects_flag_injection():
    results = await call_tool("secrets_scan", {"repo_url": "--upload-pack=touch /tmp/pwned"})
    assert "[error:invalid_repo_url]" in results[0].text


@pytest.mark.asyncio
async def test_secrets_scan_rejects_garbage_url():
    results = await call_tool("secrets_scan", {"repo_url": "definitely not a git url"})
    assert "[error:invalid_repo_url]" in results[0].text


@pytest.mark.asyncio
@patch("mcp_servers.common.requests.post")
async def test_secrets_scan_clones_then_scans(mock_post):
    mock_post.side_effect = [
        _make_response(stdout=""),  # rm -rf
        _make_response(stdout="Cloning into '...'..."),  # git clone
        _make_response(stdout="no leaks found"),  # gitleaks detect
    ]
    results = await call_tool("secrets_scan", {"repo_url": "https://github.com/org/repo.git"})
    text = results[0].text
    assert "[git clone]" in text
    assert "[gitleaks]" in text
    assert "no leaks found" in text

    sent_argvs = [c.kwargs["json"]["args"] for c in mock_post.call_args_list]
    assert sent_argvs[0][:2] == ["rm", "-rf"]
    assert sent_argvs[1][:2] == ["git", "clone"]
    assert sent_argvs[1][-1] == "/workspaces/secrets_scan_repo"
    assert sent_argvs[2][:2] == ["gitleaks", "detect"]
    assert "--redact" in sent_argvs[2]
    # Confirmed against a real gitleaks 8.30.1 binary: it emits raw ANSI
    # color codes by default even when stdout isn't a TTY, which would
    # otherwise litter the chat/LLM-visible output with escape sequences.
    assert "--no-color" in sent_argvs[2]


@pytest.mark.asyncio
@patch("mcp_servers.common.requests.post")
async def test_secrets_scan_clone_timeout_skips_gitleaks(mock_post):
    mock_post.side_effect = [
        _make_response(stdout=""),  # rm -rf
        requests.exceptions.Timeout(),  # git clone times out
    ]
    results = await call_tool("secrets_scan", {"repo_url": "https://github.com/org/repo.git"})
    assert "[error:timeout]" in results[0].text
    # Only rm + the failed clone attempt -- gitleaks never ran against a
    # nonexistent/incomplete checkout.
    assert mock_post.call_count == 2


@pytest.mark.asyncio
async def test_secrets_scan_missing_repo_url_is_required_field():
    with pytest.raises(KeyError):
        await call_tool("secrets_scan", {})


# ---- Engagement scope enforcement ---------------------------------------


@pytest.fixture
def scope_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("TOOLCHAIN_RATE_LIMIT_WINDOW", "0")
    importlib.reload(common)
    conn = sqlite3.connect(str(tmp_path / "engagements.db"))
    conn.execute(
        "CREATE TABLE engagements (id TEXT PRIMARY KEY, scope TEXT, out_of_scope TEXT, "
        "authorized_hours TEXT DEFAULT '', blackout_dates TEXT DEFAULT '[]')"
    )
    conn.execute(
        "INSERT INTO engagements (id, scope, out_of_scope) VALUES (?, ?, ?)",
        ("eng-1", json.dumps(["github.com"]), json.dumps([])),
    )
    conn.commit()
    conn.close()
    yield


@pytest.mark.asyncio
@patch("mcp_servers.common.requests.post")
async def test_secrets_scan_in_scope_host_proceeds(mock_post, scope_env):
    mock_post.side_effect = [
        _make_response(stdout=""),
        _make_response(stdout="Cloning..."),
        _make_response(stdout="no leaks found"),
    ]
    results = await call_tool("secrets_scan", {
        "repo_url": "https://github.com/org/repo.git", "engagement_id": "eng-1",
    })
    assert "[error:out_of_scope]" not in results[0].text


@pytest.mark.asyncio
async def test_secrets_scan_out_of_scope_host_blocks(scope_env):
    results = await call_tool("secrets_scan", {
        "repo_url": "https://evil-clone-target.example/org/repo.git", "engagement_id": "eng-1",
    })
    assert "[error:out_of_scope]" in results[0].text
