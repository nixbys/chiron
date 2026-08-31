"""Regression: session tokens must be stored hashed, never as the raw
plaintext dict key -- before this fix, anyone who could read
data/sessions.json could forge any active session directly from it
(ApiToken already did this correctly, next to it; sessions.json didn't)."""

import importlib
import json
import sys
import types
from pathlib import Path

from tests.helpers.import_state import clear_module


def _real_core_package():
    root = Path(__file__).resolve().parent.parent
    core_path = str(root / "core")
    core = sys.modules.get("core")
    if core is None:
        core = types.ModuleType("core")
        sys.modules["core"] = core
    core.__path__ = [core_path]
    clear_module("core.auth")
    return core


def _auth_module():
    _real_core_package()
    return importlib.import_module("core.auth")


def _make_manager(tmp_path):
    auth_mod = _auth_module()
    auth_mod._hash_password = lambda password: f"hash:{password}"
    auth_mod._verify_password = lambda password, hashed: hashed == f"hash:{password}"
    mgr = auth_mod.AuthManager(str(tmp_path / "auth.json"))
    assert mgr.create_user("alice", "old-password", is_admin=False)
    return mgr


def test_session_dict_key_is_not_the_raw_token(tmp_path):
    mgr = _make_manager(tmp_path)
    token = mgr.create_session("alice", "old-password")
    assert token not in mgr._sessions
    assert len(mgr._sessions) == 1


def test_sessions_json_on_disk_never_contains_the_raw_token(tmp_path):
    mgr = _make_manager(tmp_path)
    token = mgr.create_session("alice", "old-password")
    on_disk = json.loads(Path(mgr._sessions_path).read_text())
    assert token not in on_disk
    assert token not in json.dumps(on_disk)


def test_public_api_still_round_trips_with_the_raw_token(tmp_path):
    """The hashing is purely internal storage -- every public method still
    takes/returns the raw token, matching the browser cookie contract."""
    mgr = _make_manager(tmp_path)
    token = mgr.create_session("alice", "old-password")
    assert mgr.validate_token(token) is True
    assert mgr.get_username_for_token(token) == "alice"
    mgr.revoke_token(token)
    assert mgr.validate_token(token) is False


def test_a_raw_token_seeded_directly_into_sessions_dict_does_not_validate(tmp_path):
    """Documents the (expected, one-time) consequence of this fix: a
    pre-upgrade sessions.json full of raw-token keys does not silently
    keep working -- those sessions are invalidated, forcing a fresh login,
    same as this app's own password-change session revocation already
    does elsewhere. Not a migration bug; a deliberate simplicity choice
    for a cheap-to-reacquire credential (unlike an encrypted secret, which
    would need a real migration since it'd otherwise be unrecoverable)."""
    mgr = _make_manager(tmp_path)
    raw_token = "some-pre-upgrade-raw-token"
    with mgr._sessions_lock:
        mgr._sessions[raw_token] = {"username": "alice", "expiry": 9999999999}
    assert mgr.validate_token(raw_token) is False


def test_two_different_tokens_hash_to_different_keys(tmp_path):
    mgr = _make_manager(tmp_path)
    t1 = mgr.create_session("alice", "old-password")
    t2 = mgr.create_session("alice", "old-password")
    assert t1 != t2
    assert set(mgr._sessions.keys()).__len__() == 2  # two distinct stored keys
