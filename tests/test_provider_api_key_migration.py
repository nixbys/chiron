"""Unit tests for src/app_initializer.py's
_load_and_migrate_provider_api_keys() -- the replacement for the retired
src/api_key_manager.py's APIKeyManager.load(). Covers the same resilience
guarantees the old class's own test suite did (corrupt/wrong-shape file,
undecryptable entries, non-string values -- never a startup crash), plus
the new one-time migration off the old key onto secret_storage."""

import json
import sys

import pytest
from cryptography.fernet import Fernet


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolated secret_storage key. Deliberately does NOT pop+reimport
    src.secret_storage or src.app_initializer -- conftest.py's own eager
    `import core.database` (which runs secret_storage-dependent migrations
    at collection time) leaves sys.modules['src.secret_storage'] in a
    state where a second forced fresh import here can diverge from what
    src.app_initializer's own deferred `from src.secret_storage import
    ...` resolves to (two different module objects, two different keys).
    Patching the module already live in sys.modules keeps both call sites
    consistent -- same pattern as reusing, not fighting, the existing
    import state."""
    import src.app_initializer as app_initializer
    secret_storage = sys.modules["src.secret_storage"]
    monkeypatch.setattr(secret_storage, "_KEY_PATH", tmp_path / ".app_key")
    monkeypatch.setattr(secret_storage, "_fernet", None)
    return app_initializer, secret_storage, tmp_path


def _write_keys_json(tmp_path, data: dict):
    (tmp_path / "api_keys.json").write_text(json.dumps(data), encoding="utf-8")


def test_missing_file_returns_empty(env):
    mod, _, tmp_path = env
    assert mod._load_and_migrate_provider_api_keys(str(tmp_path)) == {}


def test_corrupt_json_returns_empty(env):
    mod, _, tmp_path = env
    (tmp_path / "api_keys.json").write_text("{not valid json", encoding="utf-8")
    assert mod._load_and_migrate_provider_api_keys(str(tmp_path)) == {}


def test_list_shape_returns_empty(env):
    mod, _, tmp_path = env
    (tmp_path / "api_keys.json").write_text('["openai", "anthropic"]', encoding="utf-8")
    assert mod._load_and_migrate_provider_api_keys(str(tmp_path)) == {}


def test_non_string_values_ignored(env):
    mod, _, tmp_path = env
    _write_keys_json(tmp_path, {"missing": None, "numeric": 42, "object": {"a": 1}})
    assert mod._load_and_migrate_provider_api_keys(str(tmp_path)) == {}


def test_already_new_format_decrypts_normally(env):
    mod, secret_storage, tmp_path = env
    _write_keys_json(tmp_path, {"brave": secret_storage.encrypt("brave-key-123")})
    assert mod._load_and_migrate_provider_api_keys(str(tmp_path)) == {"brave": "brave-key-123"}


def test_legacy_fernet_encrypted_value_is_migrated(env):
    """Simulates a pre-upgrade api_keys.json entry encrypted under the
    retired api_key_manager's separate data/.key -- must decrypt correctly
    via the legacy key AND get rewritten under the new scheme."""
    mod, secret_storage, tmp_path = env
    old_key = Fernet.generate_key()
    (tmp_path / ".key").write_bytes(old_key)
    old_ciphertext = Fernet(old_key).encrypt(b"legacy-brave-key").decode()
    _write_keys_json(tmp_path, {"brave": old_ciphertext})

    result = mod._load_and_migrate_provider_api_keys(str(tmp_path))
    assert result == {"brave": "legacy-brave-key"}

    # Rewritten on disk under the new enc: convention.
    on_disk = json.loads((tmp_path / "api_keys.json").read_text())
    assert secret_storage.is_encrypted(on_disk["brave"])
    assert secret_storage.decrypt(on_disk["brave"]) == "legacy-brave-key"


def test_garbage_value_with_no_legacy_key_is_treated_as_plaintext_and_migrated(env):
    """No data/.key on disk at all (fresh install) -- a non-enc: value is
    genuine legacy plaintext, not an undecryptable token; gets picked up
    as-is and encrypted going forward."""
    mod, secret_storage, tmp_path = env
    _write_keys_json(tmp_path, {"brave": "already-plaintext-key"})

    result = mod._load_and_migrate_provider_api_keys(str(tmp_path))
    assert result == {"brave": "already-plaintext-key"}
    on_disk = json.loads((tmp_path / "api_keys.json").read_text())
    assert secret_storage.is_encrypted(on_disk["brave"])


def test_value_undecryptable_even_under_legacy_key_falls_back_to_plaintext(env):
    """A value that isn't a valid token under the legacy key either (e.g.
    hand-edited, or encrypted under some third key) must not crash the
    migration -- treated as literal plaintext, same as the old
    APIKeyManager.load()'s own resilience guarantee."""
    mod, secret_storage, tmp_path = env
    other_key = Fernet.generate_key()
    (tmp_path / ".key").write_bytes(other_key)
    _write_keys_json(tmp_path, {"weird": "not-a-valid-fernet-token-at-all"})

    result = mod._load_and_migrate_provider_api_keys(str(tmp_path))
    assert result == {"weird": "not-a-valid-fernet-token-at-all"}


def test_mixed_providers_only_rewrites_migrated_ones(env):
    mod, secret_storage, tmp_path = env
    _write_keys_json(tmp_path, {
        "already_new": secret_storage.encrypt("kept-as-is"),
        "legacy_plain": "gets-encrypted",
    })
    result = mod._load_and_migrate_provider_api_keys(str(tmp_path))
    assert result == {"already_new": "kept-as-is", "legacy_plain": "gets-encrypted"}
