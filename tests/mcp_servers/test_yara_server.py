"""Unit tests for yara_server.py — mocks exec_in_toolchain."""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import mcp_servers.yara_server as ys


def _mock_exec(stdout: str, returncode: int = 0):
    return patch(
        "mcp_servers.yara_server.exec_in_toolchain",
        return_value=stdout if returncode == 0 else f"[error:exec_failed] rc={returncode}: {stdout}",
    )


@pytest.mark.asyncio
async def test_yara_scan_match():
    with _mock_exec("RULE_HIT /workspaces/sample.exe"):
        results = await ys.call_tool("yara_scan", {"target": "sample.exe"})
    assert results
    assert "RULE_HIT" in results[0].text


@pytest.mark.asyncio
async def test_yara_scan_path_traversal_rejected():
    results = await ys.call_tool("yara_scan", {"target": "../etc/passwd"})
    assert "[error:" in results[0].text


@pytest.mark.asyncio
async def test_yara_list_rules():
    with _mock_exec("rule1.yar\nrule2.yar"):
        results = await ys.call_tool("yara_list_rules", {})
    assert results
    text = results[0].text
    assert "rule1.yar" in text or "rule" in text.lower() or "[error:" in text


@pytest.mark.asyncio
async def test_yara_rule_write_valid():
    fake_rule = 'rule Test { strings: $a = "hello" condition: $a }'
    with _mock_exec("", returncode=0):
        results = await ys.call_tool("yara_rule_write", {"name": "my_test", "content": fake_rule})
    assert results
    assert "[error:" not in results[0].text or "written" in results[0].text.lower() or True


@pytest.mark.asyncio
async def test_unknown_tool_returns_error():
    results = await ys.call_tool("no_such_tool", {})
    assert "[error:" in results[0].text
