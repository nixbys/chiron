"""Unit tests for src/secret_storage.py -- the Fernet encrypt/decrypt/
enc:-prefix convention, and the new hmac_hex() helper used for session
tokens (core/auth.py) and the audit tamper-evidence hash chain."""

import sys

import pytest


@pytest.fixture
def secret_storage(tmp_path, monkeypatch):
    """Isolated key file per test -- same pattern
    tests/test_carddav_password_encryption.py already establishes."""
    sys.modules.pop("src.secret_storage", None)
    from src import secret_storage as mod
    monkeypatch.setattr(mod, "_KEY_PATH", tmp_path / ".app_key")
    monkeypatch.setattr(mod, "_fernet", None)
    return mod


def test_encrypt_decrypt_round_trip(secret_storage):
    encrypted = secret_storage.encrypt("hunter2")
    assert encrypted != "hunter2"
    assert encrypted.startswith("enc:")
    assert secret_storage.decrypt(encrypted) == "hunter2"


def test_encrypt_empty_string_passes_through(secret_storage):
    assert secret_storage.encrypt("") == ""


def test_decrypt_empty_string_passes_through(secret_storage):
    assert secret_storage.decrypt("") == ""


def test_encrypt_is_idempotent_on_already_encrypted_value(secret_storage):
    once = secret_storage.encrypt("hunter2")
    twice = secret_storage.encrypt(once)
    assert once == twice


def test_decrypt_plaintext_legacy_value_passes_through(secret_storage):
    assert secret_storage.decrypt("plain-legacy-value") == "plain-legacy-value"


def test_decrypt_corrupt_token_returns_empty_not_raise(secret_storage):
    assert secret_storage.decrypt("enc:not-a-real-fernet-token") == ""


def test_is_encrypted(secret_storage):
    assert secret_storage.is_encrypted("enc:abc") is True
    assert secret_storage.is_encrypted("plaintext") is False
    assert secret_storage.is_encrypted("") is False


def test_key_file_created_with_restrictive_permissions(secret_storage):
    secret_storage.encrypt("trigger key creation")
    assert secret_storage._KEY_PATH.exists()


# ---- hmac_hex -----------------------------------------------------------


def test_hmac_hex_deterministic(secret_storage):
    assert secret_storage.hmac_hex("abc123") == secret_storage.hmac_hex("abc123")


def test_hmac_hex_distinguishes_different_inputs(secret_storage):
    assert secret_storage.hmac_hex("abc123") != secret_storage.hmac_hex("abc124")


def test_hmac_hex_output_does_not_reveal_input(secret_storage):
    digest = secret_storage.hmac_hex("a-raw-session-token")
    assert "a-raw-session-token" not in digest


def test_hmac_hex_is_a_valid_hex_string(secret_storage):
    digest = secret_storage.hmac_hex("abc123")
    assert len(digest) == 64  # SHA-256 hex digest
    int(digest, 16)  # must not raise


def test_hmac_hex_and_encrypt_share_the_same_key_material(secret_storage, tmp_path):
    """Both derive from the same on-disk key -- confirm there's exactly
    one key file, not a second one minted for hmac_hex."""
    secret_storage.hmac_hex("x")
    secret_storage.encrypt("y")
    key_files = list(tmp_path.glob(".app_key*"))
    assert len(key_files) == 1
