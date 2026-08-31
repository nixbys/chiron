"""Unit tests for scripts/decrypt_export.py -- the CLI companion to
routes/export_routes.py's passphrase-encrypted exports."""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_SCRIPTS_DIR = str(Path(__file__).resolve().parents[1] / "scripts")


@pytest.fixture
def script(monkeypatch):
    if _SCRIPTS_DIR not in sys.path:
        sys.path.insert(0, _SCRIPTS_DIR)
    import decrypt_export
    return decrypt_export


def test_decrypt_round_trip(script, tmp_path):
    from routes.export_routes import encrypt_export_bytes

    enc_path = tmp_path / "export.chiron-export"
    enc_path.write_bytes(encrypt_export_bytes(b"fake zip contents", "hunter2"))
    out_path = tmp_path / "out.zip"

    with patch("getpass.getpass", return_value="hunter2"), \
         patch.object(sys, "argv", ["decrypt_export.py", str(enc_path), "-o", str(out_path)]):
        rc = script.main()

    assert rc == 0
    assert out_path.read_bytes() == b"fake zip contents"


def test_decrypt_wrong_passphrase_returns_error(script, tmp_path, capsys):
    from routes.export_routes import encrypt_export_bytes

    enc_path = tmp_path / "export.chiron-export"
    enc_path.write_bytes(encrypt_export_bytes(b"fake zip contents", "right"))

    with patch("getpass.getpass", return_value="wrong"), \
         patch.object(sys, "argv", ["decrypt_export.py", str(enc_path)]):
        rc = script.main()

    assert rc == 1
    assert "error" in capsys.readouterr().err.lower()


def test_decrypt_missing_file_returns_error(script, tmp_path, capsys):
    with patch.object(sys, "argv", ["decrypt_export.py", str(tmp_path / "nope.chiron-export")]):
        rc = script.main()
    assert rc == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_default_output_path_swaps_extension(script, tmp_path):
    from routes.export_routes import encrypt_export_bytes

    enc_path = tmp_path / "myexport.chiron-export"
    enc_path.write_bytes(encrypt_export_bytes(b"data", "pw"))

    with patch("getpass.getpass", return_value="pw"), \
         patch.object(sys, "argv", ["decrypt_export.py", str(enc_path)]):
        rc = script.main()

    assert rc == 0
    assert (tmp_path / "myexport.zip").exists()
