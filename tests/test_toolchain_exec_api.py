"""Unit tests for docker/toolchain/exec_api.py -- the Kali toolchain
sidecar's arbitrary-command-execution HTTP API. Focused on the auth
behavior fixed this pass: constant-time token comparison, and refusing to
start unauthenticated by default (see plan phase 1)."""

import importlib
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_TOOLCHAIN_DIR = str(Path(__file__).resolve().parents[1] / "docker" / "toolchain")


@pytest.fixture
def exec_api(tmp_path, monkeypatch):
    """Fresh import per test -- module-level _TOKEN/_ALLOW_INSECURE are
    read once at import time from the environment."""
    monkeypatch.setenv("EXEC_LOG_FILE", str(tmp_path / "exec_api.jsonl"))
    if _TOOLCHAIN_DIR not in sys.path:
        sys.path.insert(0, _TOOLCHAIN_DIR)
    if "exec_api" in sys.modules:
        importlib.reload(sys.modules["exec_api"])
    else:
        import exec_api as _mod  # noqa: F401
    import exec_api as mod
    return mod


def _handler_with_headers(mod, headers: dict):
    """A bare ExecHandler instance (no real HTTP connection) with just
    enough state for _authorized() to run against -- same pattern as
    testing a plain method, since BaseHTTPRequestHandler.__init__ expects
    a live socket we don't want to open here."""
    handler = mod.ExecHandler.__new__(mod.ExecHandler)
    handler.headers = headers
    return handler


def test_authorized_true_with_correct_token(exec_api, monkeypatch):
    monkeypatch.setattr(exec_api, "_TOKEN", "supersecret")
    h = _handler_with_headers(exec_api, {"Authorization": "Bearer supersecret"})
    assert h._authorized() is True


def test_authorized_false_with_wrong_token(exec_api, monkeypatch):
    monkeypatch.setattr(exec_api, "_TOKEN", "supersecret")
    h = _handler_with_headers(exec_api, {"Authorization": "Bearer wrong"})
    assert h._authorized() is False


def test_authorized_false_with_missing_header(exec_api, monkeypatch):
    monkeypatch.setattr(exec_api, "_TOKEN", "supersecret")
    h = _handler_with_headers(exec_api, {})
    assert h._authorized() is False


def test_authorized_uses_constant_time_comparison(exec_api, monkeypatch):
    """Regression: _authorized() used to compare with plain `==`, a
    timing-attack surface on the highest-value auth check in the app
    (arbitrary command execution). Confirm it now goes through
    secrets.compare_digest."""
    monkeypatch.setattr(exec_api, "_TOKEN", "supersecret")
    h = _handler_with_headers(exec_api, {"Authorization": "Bearer supersecret"})
    with patch.object(exec_api.secrets, "compare_digest", wraps=exec_api.secrets.compare_digest) as mock_cd:
        assert h._authorized() is True
    mock_cd.assert_called_once()


def test_authorized_true_when_no_token_and_insecure_allowed(exec_api, monkeypatch):
    monkeypatch.setattr(exec_api, "_TOKEN", "")
    h = _handler_with_headers(exec_api, {})
    assert h._authorized() is True


# ---- _validate_token_or_exit -------------------------------------------


def test_validate_exits_when_token_unset(exec_api, monkeypatch):
    monkeypatch.setattr(exec_api, "_TOKEN", "")
    monkeypatch.setattr(exec_api, "_ALLOW_INSECURE", False)
    with pytest.raises(SystemExit) as exc_info:
        exec_api._validate_token_or_exit()
    assert exc_info.value.code == 1


def test_validate_exits_when_token_is_the_documented_placeholder(exec_api, monkeypatch):
    """Regression: .env.example ships EXEC_API_TOKEN=change_me_before_deploy
    as a placeholder; SECURITY.md already calls this out as unsafe for any
    deployment, but nothing enforced it -- a fresh install that never
    edited .env ran the arbitrary-command-execution API on a
    publicly-documented literal string."""
    monkeypatch.setattr(exec_api, "_TOKEN", "change_me_before_deploy")
    monkeypatch.setattr(exec_api, "_ALLOW_INSECURE", False)
    with pytest.raises(SystemExit):
        exec_api._validate_token_or_exit()


def test_validate_passes_with_real_token(exec_api, monkeypatch):
    monkeypatch.setattr(exec_api, "_TOKEN", "a-real-random-token")
    monkeypatch.setattr(exec_api, "_ALLOW_INSECURE", False)
    exec_api._validate_token_or_exit()  # must not raise


def test_validate_passes_when_unset_but_insecure_allowed(exec_api, monkeypatch):
    monkeypatch.setattr(exec_api, "_TOKEN", "")
    monkeypatch.setattr(exec_api, "_ALLOW_INSECURE", True)
    exec_api._validate_token_or_exit()  # must not raise
