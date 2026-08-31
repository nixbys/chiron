"""Unit tests for core/database.py's _migrate_encrypt_notes() and
_migrate_encrypt_webhook_secrets() -- the two new startup migrations added
alongside converting Note.content/items to EncryptedText and moving
Webhook.secret off the retired src/api_key_manager.py's separate key.

Same pattern as tests/test_email_oauth.py's _make_db(): an isolated
in-memory engine, monkeypatched onto core.database.engine so the
migration functions (which read the module-level `engine` directly, not
an injected one) operate on it instead of whatever the real app is using."""

import sys

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, text


@pytest.fixture
def env(tmp_path, monkeypatch):
    import core.database as db_mod

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    db_mod.Base.metadata.create_all(engine)
    monkeypatch.setattr(db_mod, "engine", engine)

    secret_storage = sys.modules["src.secret_storage"]
    monkeypatch.setattr(secret_storage, "_KEY_PATH", tmp_path / ".app_key")
    monkeypatch.setattr(secret_storage, "_fernet", None)

    return db_mod, engine, secret_storage


def _insert_note(engine, note_id="n1", content="plain content", items=None):
    with engine.connect() as conn:
        conn.execute(
            text(
                "INSERT INTO notes (id, title, content, items, note_type, color, pinned, "
                "archived, source, sort_order, repeat, created_at, updated_at) "
                "VALUES (:id, 'Title', :content, :items, 'note', NULL, 0, 0, 'user', 0, 'none', "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            {"id": note_id, "content": content, "items": items},
        )
        conn.commit()


def _insert_webhook(engine, wh_id="w1", secret="plain-secret"):
    with engine.connect() as conn:
        conn.execute(
            text(
                "INSERT INTO webhooks (id, name, url, secret, events, is_active, created_at, updated_at) "
                "VALUES (:id, 'Test', 'https://example.com/hook', :secret, 'session.created', 1, "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            {"id": wh_id, "secret": secret},
        )
        conn.commit()


# ---- _migrate_encrypt_notes ---------------------------------------------


def test_migrate_notes_encrypts_plaintext_content_and_items(env):
    db_mod, engine, secret_storage = env
    _insert_note(engine, content="my private note", items='[{"text": "buy milk", "done": false}]')

    db_mod._migrate_encrypt_notes()

    with engine.connect() as conn:
        row = conn.execute(text("SELECT content, items FROM notes WHERE id='n1'")).fetchone()
    assert secret_storage.is_encrypted(row[0])
    assert secret_storage.is_encrypted(row[1])
    assert secret_storage.decrypt(row[0]) == "my private note"
    assert secret_storage.decrypt(row[1]) == '[{"text": "buy milk", "done": false}]'


def test_migrate_notes_is_idempotent(env):
    db_mod, engine, secret_storage = env
    _insert_note(engine, content="my private note")

    db_mod._migrate_encrypt_notes()
    with engine.connect() as conn:
        once = conn.execute(text("SELECT content FROM notes WHERE id='n1'")).scalar()

    db_mod._migrate_encrypt_notes()
    with engine.connect() as conn:
        twice = conn.execute(text("SELECT content FROM notes WHERE id='n1'")).scalar()

    assert once == twice
    assert secret_storage.decrypt(twice) == "my private note"


def test_migrate_notes_skips_null_content(env):
    db_mod, engine, secret_storage = env
    _insert_note(engine, content=None, items=None)
    db_mod._migrate_encrypt_notes()  # must not raise
    with engine.connect() as conn:
        row = conn.execute(text("SELECT content, items FROM notes WHERE id='n1'")).fetchone()
    assert row[0] is None
    assert row[1] is None


def test_migrate_notes_no_table_activity_when_already_encrypted(env):
    db_mod, engine, secret_storage = env
    _insert_note(engine, content=secret_storage.encrypt("already safe"))
    db_mod._migrate_encrypt_notes()
    with engine.connect() as conn:
        row = conn.execute(text("SELECT content FROM notes WHERE id='n1'")).scalar()
    assert secret_storage.decrypt(row) == "already safe"


# ---- _migrate_encrypt_webhook_secrets ------------------------------------


def test_migrate_webhook_secret_plaintext_gets_encrypted(env):
    db_mod, engine, secret_storage = env
    _insert_webhook(engine, secret="my-signing-secret")

    db_mod._migrate_encrypt_webhook_secrets()

    with engine.connect() as conn:
        row = conn.execute(text("SELECT secret FROM webhooks WHERE id='w1'")).scalar()
    assert secret_storage.is_encrypted(row)
    assert secret_storage.decrypt(row) == "my-signing-secret"


def test_migrate_webhook_secret_under_legacy_key_decrypts_and_reencrypts(env, tmp_path):
    """A pre-upgrade Webhook.secret encrypted under the retired
    api_key_manager's separate data/.key must decrypt correctly under
    that key and be rewritten under secret_storage's."""
    db_mod, engine, secret_storage = env
    old_key = Fernet.generate_key()
    (tmp_path / ".key").write_bytes(old_key)
    old_ciphertext = Fernet(old_key).encrypt(b"legacy-webhook-secret").decode()
    _insert_webhook(engine, secret=old_ciphertext)

    db_mod._migrate_encrypt_webhook_secrets()

    with engine.connect() as conn:
        row = conn.execute(text("SELECT secret FROM webhooks WHERE id='w1'")).scalar()
    assert secret_storage.is_encrypted(row)
    assert secret_storage.decrypt(row) == "legacy-webhook-secret"


def test_migrate_webhook_secret_is_idempotent(env):
    db_mod, engine, secret_storage = env
    _insert_webhook(engine, secret="my-signing-secret")

    db_mod._migrate_encrypt_webhook_secrets()
    with engine.connect() as conn:
        once = conn.execute(text("SELECT secret FROM webhooks WHERE id='w1'")).scalar()
    db_mod._migrate_encrypt_webhook_secrets()
    with engine.connect() as conn:
        twice = conn.execute(text("SELECT secret FROM webhooks WHERE id='w1'")).scalar()

    assert once == twice


def test_migrate_webhook_secret_skips_null_secret(env):
    db_mod, engine, secret_storage = env
    _insert_webhook(engine, secret=None)
    db_mod._migrate_encrypt_webhook_secrets()  # must not raise
    with engine.connect() as conn:
        row = conn.execute(text("SELECT secret FROM webhooks WHERE id='w1'")).scalar()
    assert row is None
