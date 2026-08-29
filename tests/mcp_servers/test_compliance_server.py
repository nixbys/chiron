"""Unit tests for compliance_server.py -- mocks requests.get (no real
network fetch) against a small synthetic OSCAL-shaped catalog."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import mcp_servers.compliance_server as cs


_FAKE_CATALOG = {
    "catalog": {
        "groups": [
            {
                "id": "ac",
                "title": "Access Control",
                "controls": [
                    {
                        "id": "ac-2",
                        "title": "Account Management",
                        "parts": [
                            {
                                "name": "statement",
                                "parts": [
                                    {"name": "item", "prose": "Define account types for {{ insert: param, ac-2_prm_1 }}."},
                                ],
                            },
                            {"name": "guidance", "prose": "Guidance text for account management."},
                        ],
                        "links": [{"rel": "related", "href": "#ia-2"}],
                        "controls": [
                            {
                                "id": "ac-2.1",
                                "title": "Automated System Account Management",
                                "parts": [
                                    {"name": "statement", "parts": [{"name": "item", "prose": "Automate account management."}]},
                                ],
                            },
                        ],
                    },
                ],
            },
            {
                "id": "ia",
                "title": "Identification and Authentication",
                "controls": [
                    {"id": "ia-2", "title": "Identification and Authentication (organizational Users)", "parts": []},
                ],
            },
        ],
    },
}


@pytest.fixture(autouse=True)
def tmp_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ODYSSEUS_DATA_DIR", str(tmp_path))
    import importlib
    importlib.reload(cs)
    yield


def _mock_fetch_response():
    resp = MagicMock()
    resp.json.return_value = _FAKE_CATALOG
    resp.raise_for_status = MagicMock()
    return resp


@pytest.mark.asyncio
async def test_nist_update_fetches_and_indexes():
    with patch("mcp_servers.compliance_server.requests.get", return_value=_mock_fetch_response()):
        results = await cs.call_tool("nist_update", {})
    text = results[0].text
    assert "3 controls" in text
    assert "2 families" in text


@pytest.mark.asyncio
async def test_nist_control_looks_up_by_id_case_insensitive():
    with patch("mcp_servers.compliance_server.requests.get", return_value=_mock_fetch_response()):
        results = await cs.call_tool("nist_control", {"control_id": "AC-2"})
    text = results[0].text
    assert "Account Management" in text
    assert "IA-2" in text  # related control, uppercased
    assert "organization-defined" in text  # param placeholder rendered


@pytest.mark.asyncio
async def test_nist_control_finds_enhancement():
    with patch("mcp_servers.compliance_server.requests.get", return_value=_mock_fetch_response()):
        results = await cs.call_tool("nist_control", {"control_id": "ac-2.1"})
    assert "Automated System Account Management" in results[0].text


@pytest.mark.asyncio
async def test_nist_control_not_found():
    with patch("mcp_servers.compliance_server.requests.get", return_value=_mock_fetch_response()):
        results = await cs.call_tool("nist_control", {"control_id": "zz-99"})
    assert "[error:not_found]" in results[0].text


@pytest.mark.asyncio
async def test_nist_family_lists_controls():
    with patch("mcp_servers.compliance_server.requests.get", return_value=_mock_fetch_response()):
        results = await cs.call_tool("nist_family", {"family_id": "ac"})
    text = results[0].text
    assert "AC-2" in text
    assert "AC-2.1" in text


@pytest.mark.asyncio
async def test_nist_family_not_found_lists_available():
    with patch("mcp_servers.compliance_server.requests.get", return_value=_mock_fetch_response()):
        results = await cs.call_tool("nist_family", {"family_id": "zz"})
    assert "Available" in results[0].text
    assert "AC" in results[0].text


@pytest.mark.asyncio
async def test_nist_search_matches_title_keyword():
    with patch("mcp_servers.compliance_server.requests.get", return_value=_mock_fetch_response()):
        results = await cs.call_tool("nist_search", {"keyword": "account"})
    text = results[0].text
    assert "AC-2" in text
    assert "AC-2.1" in text


@pytest.mark.asyncio
async def test_nist_map_covers_known_and_unmapped_items():
    results = await cs.call_tool("nist_map", {"items": ["ports", "sigma", "not-a-real-tag"]})
    text = results[0].text
    assert "Mapped items: 2" in text
    assert "Unmapped: 1" in text
    assert "not-a-real-tag" in text


@pytest.mark.asyncio
async def test_fetch_failure_reports_error_not_crash():
    with patch("mcp_servers.compliance_server.requests.get", side_effect=RuntimeError("network down")):
        results = await cs.call_tool("nist_control", {"control_id": "ac-2"})
    assert "[error:not_loaded]" in results[0].text


@pytest.mark.asyncio
async def test_unknown_tool_reports_error_not_crash():
    results = await cs.call_tool("not_a_real_tool", {})
    assert "[error:unknown_tool]" in results[0].text


@pytest.mark.asyncio
async def test_cache_reused_across_calls_no_refetch():
    fetch = MagicMock(return_value=_mock_fetch_response())
    with patch("mcp_servers.compliance_server.requests.get", fetch):
        await cs.call_tool("nist_control", {"control_id": "ac-2"})
        await cs.call_tool("nist_family", {"family_id": "ac"})
    assert fetch.call_count == 1
