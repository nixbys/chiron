"""Unit tests for sigma_server.py — uses a temp-dir rule store and mocks
OpenSearch HTTP calls. pysigma-dependent tests are skipped if the optional
dependency isn't installed in this environment (see requirements-optional.txt);
the degraded-mode tests (write/list/delete without pysigma) always run."""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

_VALID_RULE = """
title: Suspicious Test Rule
id: 11111111-1111-1111-1111-111111111111
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        title|contains: 'DownloadString'
    condition: selection
level: high
"""


@pytest.fixture(autouse=True)
def tmp_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    import importlib
    import mcp_servers.sigma_server as sigma_mod
    importlib.reload(sigma_mod)
    yield sigma_mod


@pytest.mark.asyncio
async def test_write_invalid_name_rejected(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("sigma_rule_write", {"name": "../etc/passwd", "rule_yaml": _VALID_RULE})
    assert "[error:invalid_name]" in results[0].text


@pytest.mark.asyncio
async def test_write_malformed_yaml_rejected(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("sigma_rule_write", {"name": "bad", "rule_yaml": "not: valid: yaml: ["})
    assert "[error:invalid_rule]" in results[0].text


@pytest.mark.asyncio
async def test_list_empty(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("sigma_rule_list", {})
    assert "No stored rules" in results[0].text


@pytest.mark.asyncio
async def test_delete_unknown_rule(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("sigma_rule_delete", {"name": "nope"})
    assert "[error:not_found]" in results[0].text


@pytest.mark.asyncio
async def test_convert_unknown_rule(tmp_data_dir):
    mod = tmp_data_dir
    results = await mod.call_tool("sigma_rule_convert", {"name": "nope"})
    assert "[error:not_found]" in results[0].text or "[error:not_installed]" in results[0].text


@pytest.mark.asyncio
async def test_write_and_delete_round_trip_degraded(tmp_data_dir, monkeypatch):
    """With pysigma unavailable, write falls back to a plain YAML-syntax
    check and still succeeds; convert/test report not_installed."""
    mod = tmp_data_dir
    monkeypatch.setattr(mod, "_PYSIGMA_AVAILABLE", False)

    results = await mod.call_tool("sigma_rule_write", {"name": "degraded", "rule_yaml": _VALID_RULE})
    assert "[error:" not in results[0].text
    assert "pysigma not installed" in results[0].text

    results = await mod.call_tool("sigma_rule_list", {})
    assert "degraded" in results[0].text

    results = await mod.call_tool("sigma_rule_convert", {"name": "degraded"})
    assert "[error:not_installed]" in results[0].text

    results = await mod.call_tool("sigma_rule_delete", {"name": "degraded"})
    assert "[error:" not in results[0].text


@pytest.mark.asyncio
async def test_module_import_survives_missing_pysigma(tmp_data_dir, monkeypatch):
    """Registration must never depend on the optional dependency being
    installed -- same contract as the SQLite servers' broken-data-dir guard."""
    mod = tmp_data_dir
    monkeypatch.setattr(mod, "_PYSIGMA_AVAILABLE", False)
    assert any(t.name == "sigma_rule_write" for t in mod.TOOLS)
    results = await mod.call_tool("sigma_rule_test", {"name": "anything"})
    assert "[error:not_installed]" in results[0].text


@pytest.mark.asyncio
async def test_module_import_survives_unwritable_data_dir(tmp_path, monkeypatch):
    """Same regression guard as asset_server.py, adapted for a filesystem
    (not SQLite) rule store: a broken data dir must not crash registration,
    and sigma_rule_list must fail cleanly rather than raise."""
    import importlib
    import mcp_servers.sigma_server as sigma_mod

    bogus_data_dir = tmp_path / "data"
    bogus_data_dir.write_text("not a directory")

    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(bogus_data_dir))
    importlib.reload(sigma_mod)

    assert any(t.name == "sigma_rule_write" for t in sigma_mod.TOOLS)

    results = await sigma_mod.call_tool("sigma_rule_list", {})
    assert "[error:" in results[0].text


@pytest.mark.asyncio
async def test_write_and_convert_real_pysigma(tmp_data_dir):
    mod = tmp_data_dir
    if not mod._PYSIGMA_AVAILABLE:
        pytest.skip("pysigma-backend-opensearch not installed")

    results = await mod.call_tool("sigma_rule_write", {"name": "real_rule", "rule_yaml": _VALID_RULE})
    assert "[error:" not in results[0].text

    results = await mod.call_tool("sigma_rule_convert", {"name": "real_rule"})
    assert "[error:" not in results[0].text
    assert "DownloadString" in results[0].text


@pytest.mark.asyncio
async def test_sigma_rule_test_against_mocked_opensearch(tmp_data_dir):
    mod = tmp_data_dir
    if not mod._PYSIGMA_AVAILABLE:
        pytest.skip("pysigma-backend-opensearch not installed")

    await mod.call_tool("sigma_rule_write", {"name": "real_rule", "rule_yaml": _VALID_RULE})

    mock_response = {
        "hits": {
            "total": {"value": 1},
            "hits": [{"_id": "abc", "_source": {"title": "Suspicious download", "severity": "high"}}],
        }
    }
    with patch("mcp_servers.sigma_server._os_search", return_value=mock_response):
        results = await mod.call_tool("sigma_rule_test", {"name": "real_rule"})
    text = results[0].text
    assert "Matches: 1" in text
    assert "Suspicious download" in text
